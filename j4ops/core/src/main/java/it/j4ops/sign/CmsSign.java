/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign;


import it.j4ops.CmsSignMode;
import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import it.j4ops.sign.cms.ExternalCMSSignedDataGenerator;
import it.j4ops.sign.cms.ExternalSignerInfoGenerator;
import it.j4ops.sign.provider.IaikPKCS11Provider;
import it.j4ops.sign.provider.PKCS12Provider;
import it.j4ops.sign.provider.SignProvider;
import it.j4ops.util.DERUtil;
import it.j4ops.util.TimeStampTokenUtil;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.log4j.xml.DOMConfigurator;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.CollectionStore;

/**
 *
 * @author fzanutto
 */
public class CmsSign extends BaseSign {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    public CmsSign (SignProvider signProvider, SignHandler signHandler, Properties properties) {
        super(signProvider, signHandler, properties);        
    } 

    public void sign (Date signingTime, CmsSignMode cmsSignMode, InputStream srcIS, OutputStream destOS) throws Exception {
        byte[] contentBytes = null;        

        // check if need inizialization
        if (!isInitialized()) {
            throw new Exception ("need initialization");
        }        
        
        // get data input
        contentBytes = DERUtil.streamToByteArray(srcIS);  

        // check if convert from b64
        if (Base64.isBase64(contentBytes)) {
            contentBytes = Base64.decodeBase64(contentBytes);
        }           

        // get certificate selected 
        X509Certificate x509Cert = getSignProvider().getX509Certificate();
        List<X509Certificate> x509CertChain = getCertificateChain();        

        // create external CMS signed data            
        ExternalCMSSignedDataGenerator externalCMSSignedDataGenerator = new ExternalCMSSignedDataGenerator(contentBytes, getProperty(SecurityProvider.getLiteral()));             

        // create external siger info generator
        ExternalSignerInfoGenerator externalSignerInfoGenerator = new ExternalSignerInfoGenerator (getEnvelopeSignType(), getDigestAlgOID(), 
                                                                                                   getEncryptionAlgOID(), getProperty(SecurityProvider.getLiteral()));            

        // calcolate hash
        byte[] hash = DERUtil.getHash(externalCMSSignedDataGenerator.getContent(), getDigestAlgOID(), getProperty(SecurityProvider.getLiteral()));

        // check if add TimeStampToken
        TimeStampToken timeStampToken = null;
        if (getEnvelopeSignType() == SignType.CAdES_T || 
            getEnvelopeSignType() == SignType.PAdES_T || 
            getEnvelopeSignType() == SignType.XAdES_T) {            
            timeStampToken = TimeStampTokenUtil.getTimeStampToken(new URL(getProperty(TSAURL.getLiteral())), 
                                                                  getProperty(TSAUser.getLiteral()), 
                                                                  getProperty(TSAPassword.getLiteral()), 
                                                                  hash, getDigestAlgOID(), BigInteger.ZERO, 
                                                                  getProperty(SecurityProvider.getLiteral()));
            // validate TSA certificate 
            validateTimeStampToken(timeStampToken); 
        }          

        // take bytes to sign
        byte[] toEncrypt = externalSignerInfoGenerator.getP7xBytesToSign(hash, signingTime, PKCSObjectIdentifiers.data,
                                                                         x509Cert, timeStampToken);

        // sign date
        byte [] signature = getSignProvider().sign(toEncrypt);

        // add signe information
        externalCMSSignedDataGenerator.addSignerInfoGenerator(externalSignerInfoGenerator.generate(hash, signature, x509Cert));

        // add certificates if not exists
        X509CertificateHolder certHolder = new X509CertificateHolder(x509Cert.getEncoded());
        if (!externalCMSSignedDataGenerator.getCertificates().getMatches(null).contains(certHolder)) {
            List <X509CertificateHolder> lstCertsHolder = new ArrayList<X509CertificateHolder>();
            for (X509Certificate cert : x509CertChain) { 
                lstCertsHolder.add(new X509CertificateHolder(cert.getEncoded()));
            } 
            externalCMSSignedDataGenerator.addCertificates(new CollectionStore(lstCertsHolder));
        }        

        // create signed envelope
        CMSSignedData envdata = externalCMSSignedDataGenerator.generate((cmsSignMode == CmsSignMode.Attached)?true:false);                
        byte[] enveloped = envdata.getEncoded();

        logger.info (String.format("envelope pkcs7 length:%d", enveloped.length));   

        // check envelope encoded
        if ("B64".equalsIgnoreCase(getProperty(EnvelopeEncode.getLiteral()))) {
            destOS.write(Base64.encodeBase64(enveloped, true));           
        }
        else if ("DER".equalsIgnoreCase(getProperty(EnvelopeEncode.getLiteral()))) {
            destOS.write(enveloped);        
        }
        else {
            throw new Exception (String.format("Envelope encode not know %s", getProperty(EnvelopeEncode.getLiteral())));
        }
        destOS.flush();                            
    }

    public void addSign (Date signingTime, CmsSignMode cmsSignMode, InputStream srcIS, OutputStream destOS) throws Exception {    
        sign (signingTime, cmsSignMode, srcIS, destOS);
    }
            
    public void counterSign (Date signingTime, CmsSignMode cmsSignMode, InputStream srcIS, OutputStream destOS) throws Exception {
        byte[] contentBytes = null;        
        
        // check if need inizialization
        if (!isInitialized()) {
            throw new Exception ("need initialization");
        }            
        
        // get data input
        contentBytes = DERUtil.streamToByteArray(srcIS);  

        // check if convert from b64
        if (Base64.isBase64(contentBytes)) {
            contentBytes = Base64.decodeBase64(contentBytes);
        }          

        // get certificate selected 
        X509Certificate x509Cert = getSignProvider().getX509Certificate();
        List<X509Certificate> x509CertChain = getCertificateChain();        

        // create external CMS signed data            
        ExternalCMSSignedDataGenerator externalCMSSignedDataGenerator = new ExternalCMSSignedDataGenerator(contentBytes, getProperty(SecurityProvider.getLiteral()));             

        // create external siger info generator
        ExternalSignerInfoGenerator externalSignerInfoGenerator = new ExternalSignerInfoGenerator (getEnvelopeSignType(), getDigestAlgOID(), 
                                                                                                   getEncryptionAlgOID(), getProperty(SecurityProvider.getLiteral()));            

        // select signer to countsign
        SignerInformation selectSigner = getSignHandler().selectSigner(externalCMSSignedDataGenerator.getCertificates(), externalCMSSignedDataGenerator.getSignerInfos());
        if (selectSigner != null) {

            // calcolate hash to signature
            byte[] hash = DERUtil.getHash(selectSigner.getSignature(), 
                                          getDigestAlgOID(), getProperty(SecurityProvider.getLiteral()));

            // check if add TimeStampToken
            TimeStampToken timeStampToken = null;
            if (getEnvelopeSignType() == SignType.CAdES_T || 
                getEnvelopeSignType() == SignType.PAdES_T || 
                getEnvelopeSignType() == SignType.XAdES_T) {            
                timeStampToken = TimeStampTokenUtil.getTimeStampToken(new URL(getProperty(TSAURL.getLiteral())), 
                                                                      getProperty(TSAUser.getLiteral()), 
                                                                      getProperty(TSAPassword.getLiteral()), 
                                                                      hash, getDigestAlgOID(), BigInteger.ZERO, 
                                                                      getProperty(SecurityProvider.getLiteral()));
                // validate TSA certificate 
                validateTimeStampToken(timeStampToken);                
            }           

            // take bytes to sign without context type
            byte[] toEncrypt = externalSignerInfoGenerator.getP7xBytesToSign(hash, signingTime, null,
                                                                             x509Cert, timeStampToken);
            // sign date
            byte [] signature = getSignProvider().sign(toEncrypt);

            // add counter signer to sign
            externalCMSSignedDataGenerator.addCounterSigner(selectSigner, 
                externalSignerInfoGenerator.generate(hash, signature, x509Cert));

            // add certificates if not exists
            X509CertificateHolder certHolder = new X509CertificateHolder(x509Cert.getEncoded());
            if (!externalCMSSignedDataGenerator.getCertificates().getMatches(null).contains(certHolder)) {
                List <X509CertificateHolder> lstCertsHolder = new ArrayList<X509CertificateHolder>();
                for (X509Certificate cert : x509CertChain) { 
                    lstCertsHolder.add(new X509CertificateHolder(cert.getEncoded()));
                } 
                externalCMSSignedDataGenerator.addCertificates(new CollectionStore(lstCertsHolder));
            }

            // create signed envelope
            CMSSignedData envdata = externalCMSSignedDataGenerator.generate((cmsSignMode == CmsSignMode.Attached)?true:false);      

            byte[] enveloped = envdata.getEncoded();

            logger.info (String.format("envelope pkcs7 length:%d", enveloped.length));             

            // check envelope encoded
            if ("B64".equalsIgnoreCase(getProperty(EnvelopeEncode.getLiteral()))) {
                destOS.write(Base64.encodeBase64(enveloped, true));           
            }
            else if ("DER".equalsIgnoreCase(getProperty(EnvelopeEncode.getLiteral()))) {
                destOS.write(enveloped);        
            }
            else {
                throw new Exception (String.format("Envelope encode not know %s", getProperty(EnvelopeEncode.getLiteral())));
            }
            destOS.flush();               
        }                                       
    }    
    
    public static void main (String []args) throws Exception {
        
        String pin = "12345678";
        //spdfza String pin = "87654321";

        
        DOMConfigurator.configure("log4j.xml"); 
                
        SignProvider signProvider = null;     
        SignHandler signHandler = null;
        if (args.length <= 0) {
            signHandler = new BaseSignHandler("sign");            
            signProvider = new PKCS12Provider("j4ops.p12");
        }
        else {
            signHandler = new BaseSignHandler(pin);            
            
            signProvider = new IaikPKCS11Provider("tokens.xml");
            //signProvider = new SunPKCS11Provider("tokens.xml");
        }
        
        Properties prop = new Properties ();
        prop.setProperty(SecurityProvider.getLiteral(), "BC");        
        prop.setProperty(DigestAlgName.getLiteral(), "SHA256"); 
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "CAdES_BES");
        prop.setProperty(EnvelopeEncode.getLiteral(), "B64");        
        prop.setProperty(EnvelopeSignType.getLiteral(), "CAdES_T"); 
        prop.setProperty(TSAURL.getLiteral(), "http://timestamping.edelweb.fr/service/tsp");
        //prop.setProperty(TSAURL.getLiteral(), "http://dse200.ncipher.com/TSS/HttpTspServer");
        //prop.setProperty(TSAURL.getLiteral(), "http://ns.szikszi.hu:8080/tsa");
        prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "testCA.ks"); 
        prop.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");         
        
        CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop);
        
        
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
        Date date = sdf.parse("120104213756");

        System.out.println ("date:" + date);
        
        // sign
        FileInputStream fis = new FileInputStream ("libre.pdf");      
        FileOutputStream fos = new FileOutputStream ("sign.p7m");   
        try {
            cmsSign.init();
            cmsSign.sign(date, CmsSignMode.Attached, fis, fos);
        }
        finally {
            cmsSign.destroy();
        }
        fis.close();
        fos.close();        
        
        // counter sign
        fis = new FileInputStream ("sign.p7m");      
        fos = new FileOutputStream ("sign_counter.p7m");   
        try {
            cmsSign.init();
            cmsSign.counterSign(date, CmsSignMode.Attached, fis, fos);
        }
        finally {
            cmsSign.destroy();
        }        
        fis.close();
        fos.close();   
        
        // add sign
        fis = new FileInputStream ("sign_counter.p7m");      
        fos = new FileOutputStream ("sign_add.p7m");
        try {
            cmsSign.init();
            cmsSign.addSign(date, CmsSignMode.Attached, fis, fos);
        }
        finally {
            cmsSign.destroy();
        }        
        fis.close();
        fos.close();        
      
        System.out.println ("Fine!");
    }
}
