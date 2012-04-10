/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.util;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.util.*;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author fzanutto
 */
public class TimeStampTokenUtil {
    private static Logger logger = Logger.getLogger(X509Util.class);    

    public static X509Certificate validateTimeStampToken (TimeStampToken timeStampToken, Set<X509Certificate> trustedCerts, final String securityProvider) throws Exception {

        SignerId signerId = timeStampToken.getSID();
        BigInteger certSerialNumber = signerId.getSerialNumber();
        CertStore cs = timeStampToken.getCertificatesAndCRLs("Collection", securityProvider);
        Collection certs = cs.getCertificates(null);

        Iterator<X509Certificate> iter = certs.iterator();
        X509Certificate x509Certificate = null;
        while (iter.hasNext()) {
            X509Certificate x509Cert = iter.next();
            if (certSerialNumber != null) {
                if (x509Cert.getSerialNumber().equals(certSerialNumber)) {
                    logger.debug ("using certificate with serial: " + x509Cert.getSerialNumber());
                    x509Certificate = x509Cert;
                }
            } else {
                if (x509Certificate == null) {
                    x509Certificate = x509Cert;
                }
            }
            logger.debug ("Certificate subject dn " + x509Cert.getSubjectDN());
            logger.debug ("Certificate serial " + x509Cert.getSerialNumber());
        }

        logger.debug ("validateCertificate:" + x509Certificate.getSubjectDN());
        TSPUtil.validateCertificate(x509Certificate);
        
        logger.debug ("checkValidity:" + x509Certificate.getSubjectDN());
        x509Certificate.checkValidity();
        
        // checking for ExtendedKeyUsage only for TSA ceretificates
        PKIXCertPathChecker pkixCertPathChecker = new PKIXCertPathChecker() {

            @Override
            public void init(boolean forward) throws CertPathValidatorException {
            }

            @Override
            public boolean isForwardCheckingSupported() {
                return true;
            }

            @Override
            public Set<String> getSupportedExtensions() {
                return Collections.EMPTY_SET;
            }

            @Override
            public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
                try {
                    X509Certificate x509Cert = X509Util.toX509Certificate(cert.getEncoded(), securityProvider);
                    if (x509Cert.getExtendedKeyUsage() != null) {
                        List<String> lstExtendedKeyUsage = x509Cert.getExtendedKeyUsage();
                        if (lstExtendedKeyUsage.size() == 1 && lstExtendedKeyUsage.contains(KeyPurposeId.id_kp_timeStamping.getId())) {
                            if( unresolvedCritExts.contains (X509Extension.extendedKeyUsage.getId())){ 
                                unresolvedCritExts.remove(X509Extension.extendedKeyUsage.getId()); 
                            } 
                        }
                    }
                }
                catch (Exception ex) {
                    logger.fatal(ex.toString(), ex);
                    throw new CertPathValidatorException (ex.toString(), ex);
                }
            }        
        };       
        
        logger.debug ("validateChain:" + x509Certificate.getSubjectDN());
        X509Util.validateChain (x509Certificate, trustedCerts, pkixCertPathChecker, securityProvider);

        return x509Certificate;  
    }
    
    
    
    public static TimeStampToken getTimeStampToken(URL url, String user, String password, 
                                                   byte[] fingerPrint, String digestAlgOID, BigInteger nonce, String securityProvider) throws 
                                                   IOException, TSPException, NoSuchAlgorithmException, 
                                                   NoSuchProviderException, CMSException, CertStoreException, 
                                                   TSPValidationException, CertificateExpiredException, CertificateNotYetValidException {

        logger.info(String.format("getTimeStampToken (%s, %s, %s, %s, %s, %d, %s)", url.toString(), user, password, 
                                                                                HexString.hexify(fingerPrint), digestAlgOID, nonce, securityProvider));
        logger.info(String.format("hash:%s len:%d", HexString.hexify(fingerPrint), fingerPrint.length));
        
        PostMethod method = new PostMethod (url.toString());
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        
        //request TSA to return certificate
        reqGen.setCertReq(true);

        //make a TSP request this is a dummy sha1 hash (20 zero bytes) and nonce=100
        TimeStampRequest request = reqGen.generate(digestAlgOID, fingerPrint, nonce);
        byte[] encReq = request.getEncoded();

        method.setRequestEntity (new ByteArrayRequestEntity(encReq));
        method.setRequestHeader("Content-type", "application/timestamp-query");
        if ((user != null && !"".equals(user)) &&
            (password != null && !"".equals(password))) {
            String userPassword = user + ":" + password;
            String basicAuth = "Basic " + new String(Base64.encode(userPassword.getBytes()));
            method.setRequestHeader("Authorization", basicAuth);            
            logger.debug("add baisc authorization:" + basicAuth);
        }

        HttpClient httpClient = new HttpClient();
        httpClient.executeMethod(method);
        InputStream in = method.getResponseBodyAsStream();

        //read TSP response
        TimeStampResponse resp = new TimeStampResponse(in);     
        if (resp.getStatus() != 0) {            
            throw new TSPException (String.format("response error status %d - %s", resp.getStatus(), resp.getStatusString()));
        }
        resp.validate(request);                   
        logger.debug ("TimestampResponse validated");

        TimeStampToken timeStampToken = resp.getTimeStampToken();

        logger.debug("TimeStampToken: " + HexString.hexify(timeStampToken.getEncoded()));

        return timeStampToken;
    }
    
    public static void main (String []args) throws Exception {
        URL url = new URL("http://tsa.swisssign.net");
        
        //URL url = new URL("http://timestamping.edelweb.fr/service/tsp");
        //URL url = new URL("http://tss.pki.gva.es:8318/tsa");
        //byte []hash = HexString.parseHexString("A6E4E9F5BBF46B694736A105C972D203E21FDEA9");//new byte [20];
        byte []hash = HexString.parseHexString("A6E4E9F5BBF46B694736A105C972D203E21FDEA926ABED9DF7A7AA5C5AE68FAA");
        
        DOMConfigurator.configure("log4j.xml");        
        Security.addProvider(new BouncyCastleProvider());        
        
        System.out.println("hash " + hash.length + " bytes");         
        
        //----- request timestamp ------------
        TimeStampToken tst = TimeStampTokenUtil.getTimeStampToken(url, null, null, hash, TSPAlgorithms.SHA256, BigInteger.valueOf(0), "BC");

        if (tst == null) {
            System.out.println("NO TST");
            return;
        }
        byte[] tsrdata = tst.getEncoded();
        
        FileOutputStream fos = new FileOutputStream ("prova.txt");
        fos.write (HexString.hexify(tsrdata).getBytes());
        fos.flush();
        fos.close();

        System.out.println("Got tsr " + tsrdata.length + " bytes");
    }    
}
