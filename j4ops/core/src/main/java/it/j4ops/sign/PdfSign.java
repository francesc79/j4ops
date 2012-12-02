/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign;



import com.itextpdf.text.pdf.*;
import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import it.j4ops.sign.cms.ExternalCMSSignedDataGenerator;
import it.j4ops.sign.cms.ExternalSignerInfoGenerator;
import it.j4ops.sign.provider.IaikPKCS11Provider;
import it.j4ops.sign.provider.PKCS12Provider;
import it.j4ops.sign.provider.SignProvider;
import it.j4ops.util.DERUtil;
import it.j4ops.util.HexString;
import it.j4ops.util.TimeStampTokenUtil;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.log4j.xml.DOMConfigurator;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.CollectionStore;

/**
 *
 * @author fzanutto
 */
public class PdfSign extends BaseSign {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static final int CONTENTS_SIZE = 0x2830;
    
    public PdfSign (SignProvider signProvider, SignHandler signHandler, Properties properties) {
        super(signProvider, signHandler, properties); 
    }    
    
    public void sign (Date signingTime, InputStream srcIS, String ownerPassword, OutputStream destOS) throws Exception {        
        // check if need inizialization
        if (!isInitialized()) {
            throw new Exception ("need initialization");
        }            

        // get certificate selected 
        X509Certificate x509Cert = getSignProvider().getX509Certificate();    
        List<X509Certificate> x509CertChain = getCertificateChain();

        // read pdf
        PdfReader reader = new PdfReader(srcIS, (ownerPassword != null)?ownerPassword.getBytes():null);

        // get numbers of signatures
        AcroFields af = reader.getAcroFields();
        ArrayList<String> lstSignatureNames = af.getSignatureNames();
        for (String name : lstSignatureNames) {
            logger.debug ("Signature name: " + name);
            logger.debug ("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
            logger.debug ("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
        }

        // decide first or more sign
        PdfStamper stamper = null;
        if (lstSignatureNames.size() <= 0) {
            stamper = PdfStamper.createSignature(reader, destOS, '\0');
            logger.debug("create first signature");
        }
        else {
            stamper = PdfStamper.createSignature(reader, destOS, '\0', null, true);
            logger.debug("add signature");
        }
        if (ownerPassword != null) {
            stamper.setEncryption(ownerPassword.getBytes(), ownerPassword.getBytes(), reader.getPermissions(), true);
        }
        
        // add signature information
        PdfSignatureAppearance sap = stamper.getSignatureAppearance();
        sap.setCrypto(null, x509CertChain.toArray(new X509Certificate[0]), null, PdfSignatureAppearance.SELF_SIGNED);
        sap.setReason("j4opsPDF");

        //sap.setVisibleSignature(new Rectangle(0, 0, 1, 1), 1, null);
        //sap.setVisibleSignature(new Rectangle(340, 600, 560, 700), 1, null);
        sap.setExternalDigest(new byte[128], new byte[20], getProperty(EncryptionAlgName.getLiteral()));

        Calendar cal = Calendar.getInstance();
        cal.setTime(signingTime);
        PdfDictionary dic = new PdfDictionary();
        dic.put(PdfName.FT, PdfName.SIG);
        dic.put(PdfName.FILTER, new PdfName("Adobe.PPKLite"));
        dic.put(PdfName.SUBFILTER, new PdfName("adbe.pkcs7.detached"));
        dic.put(PdfName.M, new PdfDate(cal));
        dic.put(PdfName.NAME, new PdfString(PdfPKCS7.getSubjectFields(x509Cert).getField("CN")));

        // is normal signature
        sap.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
        sap.setCryptoDictionary(dic);
        
        /* certified signatur */        
        // PdfDictionary reference = new PdfDictionary();
        // reference.put(new PdfName("TransformMethod"), new PdfName("DocMDP"));
        // reference.put(PdfName.TYPE, new PdfName("SigRef"));
        //
        // PdfDictionary transformParams = new PdfDictionary();
        // transformParams.put(PdfName.P, new PdfNumber((flagAddSign == true)?0:2));
        // transformParams.put(PdfName.V, new PdfName("1.2"));
        // transformParams.put(PdfName.TYPE, new PdfName("TransformParams"));        
        // reference.put(new PdfName("TransformParams"), transformParams);
        //
        // PdfArray types = new PdfArray();
        // types.add(reference);
        // dic.put(new PdfName("Reference"), types);

        HashMap exc = new HashMap();
        exc.put(PdfName.CONTENTS, CONTENTS_SIZE + 2);
        sap.preClose(exc);

        // create external CMS signed data
        ExternalCMSSignedDataGenerator externalCMSSignedDataGenerator = 
            new ExternalCMSSignedDataGenerator(new CMSProcessableByteArray(DERUtil.streamToByteArray(sap.getRangeStream())));

        // create external siger info generator
        ExternalSignerInfoGenerator externalSignerInfoGenerator = 
            new ExternalSignerInfoGenerator (getEnvelopeSignType(), getDigestAlgOID(), 
                                             getEncryptionAlgOID(), getProperty(SecurityProvider.getLiteral()));                                           

        // calcolate hash
        byte[] hash = DERUtil.getHash(externalCMSSignedDataGenerator.getContent(), getDigestAlgOID(), getProperty(SecurityProvider.getLiteral()));

        logger.debug("HASH:" + HexString.hexify(hash));

        // generate TimeStampToken
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
        byte[] toEncrypt = externalSignerInfoGenerator.getPdfBytesToSign(hash, signingTime, PKCSObjectIdentifiers.data, 
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

        // build signature envelope
        CMSSignedData envdata = externalCMSSignedDataGenerator.generate (false);                
        byte[] encodedPkcs7 = envdata.getEncoded();            

        byte out[] = new byte[CONTENTS_SIZE/2];
        System.arraycopy(encodedPkcs7, 0, out, 0, encodedPkcs7.length);

        PdfDictionary dic2 = new PdfDictionary();        
        dic2.put(PdfName.CONTENTS, new PdfString(out).setHexWriting(true));
        sap.close(dic2);    
    }
    
    public void addSign (Date signingTime, InputStream srcIS, String ownerPassword, OutputStream destOS) throws Exception {
        sign (signingTime, srcIS, ownerPassword, destOS);
    }       

    public static void main (String []args) throws Exception {
        

        DOMConfigurator.configure("log4j.xml");        
        
        String pin = "12345678";

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
        prop.setProperty(DigestAlgName.getLiteral(), "SHA256"); 
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "PAdES_BES");      
        prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "testCA.ks"); 
        prop.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");         
        //prop.setProperty(EnvelopeSignType.getLiteral(), "PAdES_T");       
        prop.setProperty(TSAURL.getLiteral(), "http://timestamping.edelweb.fr/service/tsp");
        
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
        Date date = sdf.parse("120205091850");

        System.out.println ("date:" + date);  
        
        //date = new Date();
        
        PdfSign pdfSign = new PdfSign (signProvider, signHandler, prop);
        
        FileInputStream fis = new FileInputStream ("libre.pdf");      
        FileOutputStream fos = new FileOutputStream ("libre_sign.pdf");
        try {
            pdfSign.init();
            pdfSign.sign(date, fis, null, fos);
        }
        finally {
            pdfSign.destroy();
        }         
        fis.close();
        fos.close();
        
        /*
        fis = new FileInputStream ("sign.pdf");      
        fos = new FileOutputStream ("sign_add.pdf");                 
        try {
            pdfSign.init();
            pdfSign.addSign(date, fis, fos);
        }
        finally {
            pdfSign.destroy();
        }
        fis.close();
        fos.close();
        * 
        */
    }    
}
