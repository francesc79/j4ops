/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.verify;

import static it.j4ops.PropertyConstants.VerifyCertificate;
import it.j4ops.SignType;
import it.j4ops.util.DERUtil;
import it.j4ops.util.DNParser;
import it.j4ops.verify.bean.SignerInfo;
import it.j4ops.verify.bean.VerifyInfo;
import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;

/**
 *
 * @author fzanutto
 */
public class CmsVerify extends BaseVerify {
    private Logger logger = Logger.getLogger(this.getClass());       
    
    public CmsVerify (Properties properties) {
        super(properties);
    }
    
    protected SignerInfo verifySignature (Store certs, SignerInformation signer, int level) throws Exception {
        SignerId signerId = signer.getSID();
        SignerInfo signerInfo = null;

        Collection certCollection = certs.getMatches(signerId);
        Iterator certIter = certCollection.iterator();
        while (certIter.hasNext()) {
            X509CertificateHolder certHolder = (X509CertificateHolder) certIter.next();
            SignerInformationVerifier verifier = new SignerInformationVerifier(
                new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(certHolder), 
                new BcDigestCalculatorProvider());

            if (signer.verify(verifier) == true) {
                Attribute attrSigningTime = signer.getSignedAttributes().get(CMSAttributes.signingTime);
                Enumeration enumer = attrSigningTime.getAttrValues().getObjects();
                ASN1UTCTime dateSign = (ASN1UTCTime)enumer.nextElement();                

                // create signer informations
                signerInfo = new SignerInfo ();
                signerInfo.setAuthor(DNParser.parse(certHolder.getSubject().toString(), "CN"));
                signerInfo.setDateSign(dateSign.getDate());
                signerInfo.setCounterSignature(signer.isCounterSignature());
                signerInfo.setSignerInformation(signer);
                signerInfo.setLevel(level);

                // check signed type
                if (signer.getSignedAttributes() != null && signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) != null) {
                    signerInfo.setSignType(SignType.CAdES_BES); 
                    if (signer.getUnsignedAttributes() != null && signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
                        signerInfo.setSignType(SignType.CAdES_T);                        
                        if (signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs) != null &&
                            signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs) != null) {
                            signerInfo.setSignType(SignType.CAdES_C);
                        }
                    }                    
                }
                else {
                    signerInfo.setSignType(SignType.Pkcs7);
                }                
                
                // get certificate
                CertificateFactory cf = CertificateFactory.getInstance("X.509"); 
                InputStream is = null;
                try {
                    is = new ByteArrayInputStream(certHolder.toASN1Structure().getEncoded());
                    signerInfo.setX509Cert((X509Certificate) cf.generateCertificate(is));
                } 
                finally {
                    try {
                        if (is != null) {
                            is.close(); 
                            is = null;
                        }
                    }
                    catch (Exception ex) {}
                }
                
                // validate certificate
                if (Boolean.valueOf(getProperty(VerifyCertificate.getLiteral()))) {
                    validateCertificate(signerInfo);
                }
                
                logger.info ("Verified!");   
                logger.info (String.format("Level:%d", level));
                logger.info (String.format("SignType:%s", signerInfo.getSignType()));                 
                logger.info (String.format("DateSign:%s", new SimpleDateFormat("dd-MM-yyyy hh:mm:ss").format(signerInfo.getDateSign()))); 
                logger.info (String.format("Author:%s", signerInfo.getAuthor()));   
                logger.info (String.format("isCounterSignature:%b", signerInfo.isCounterSignature()));                   
            }
        } 
        return signerInfo;
    }
    
    protected void verifyCounterSignatures (SignerInfo signerInfo, int level, Store certs, SignerInformationStore counterSignatures) throws Exception {
        Collection lstCounterSigners = counterSignatures.getSigners();
        Iterator iter = lstCounterSigners.iterator();  
        level ++;
        while (iter.hasNext()) {
            SignerInformation signer = (SignerInformation) iter.next();
            SignerInfo si = verifySignature (certs, signer, level);
            verifyCounterSignatures (si, level, certs, signer.getCounterSignatures());
            signerInfo.addSignerInfo(si);
        }
    }
    
    public VerifyInfo verify (InputStream envelopeIS, InputStream dataIS, OutputStream outputStream) throws Exception {
        VerifyInfo verifyInfo = new VerifyInfo ();
        CMSSignedData signedData = null;

        byte content[] = null;
        if (dataIS == null) {
            content = DERUtil.streamToByteArray(envelopeIS);
            
            // check if convert from b64
            if (Base64.isBase64(content) == true) {
                content = Base64.decodeBase64(content);
            }

            // parsing signed data
            signedData = new CMSSignedData(content);
        }
        else {            
            try {
                content = new byte [dataIS.available()]; 
                dataIS.read(content);
            }
            finally {
                dataIS.close();
            }
            signedData = new CMSSignedData(new CMSProcessableByteArray(content), envelopeIS);
        }
        CMSProcessable signedContent = signedData.getSignedContent();
        if (signedContent != null && outputStream != null) {
            signedContent.write(outputStream);
            outputStream.flush();
        }
        Store certs = signedData.getCertificates();        
        SignerInformationStore signers = signedData.getSignerInfos();
        Collection lstSigners = signers.getSigners();
        Iterator iter = lstSigners.iterator();       
        int level = 0;
        while (iter.hasNext()) {
            SignerInformation signer = (SignerInformation) iter.next();
            SignerInfo signerInfo = verifySignature (certs, signer, level);
            verifyCounterSignatures (signerInfo, level, certs, signer.getCounterSignatures());  
            verifyInfo.addSignerInfo(signerInfo);
        }        
        return verifyInfo;
    }
    
    public static void main (String []args) throws Exception {
        DOMConfigurator.configure("log4j.xml");
        Properties prop = new Properties ();      
        CmsVerify cmsVerify = new CmsVerify (prop);
        
        FileInputStream fis = null;
        FileOutputStream fos = null;
        
        try {
            //fis = new FileInputStream ("3_counter.pdf.p7m");
            //fis = new FileInputStream ("sign_dike.p7m");
            fis = new FileInputStream ("doc_firmato_con_il_vecchio_framework.p7m");
            fos = new FileOutputStream ("sign_verified.pdf");
            VerifyInfo vi = cmsVerify.verify(fis, null, fos);            
            System.out.println (String.format("count signs:%d", vi.getCountSigns()));
        }
        finally {
            try {
                if (fis != null) {
                    fis.close();
                    fis = null;
                }
            }
            catch (IOException ex) {}
            try {
                if (fos != null) {
                    fos.close();
                    fos = null;
                }
            }
            catch (IOException ex) {}            
        }
        
    }

}
