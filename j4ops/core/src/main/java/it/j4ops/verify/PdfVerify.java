/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.verify;


import com.itextpdf.text.pdf.*;
import static it.j4ops.PropertyConstants.VerifyCertificate;
import it.j4ops.SignType;
import it.j4ops.util.DNParser;
import it.j4ops.verify.bean.SignerInfo;
import it.j4ops.verify.bean.VerifyInfo;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

/**
 *
 * @author fzanutto
 */
public class PdfVerify extends BaseVerify {
    private Logger logger = Logger.getLogger(this.getClass());       
    
    public PdfVerify (Properties properties) {
        super(properties);
    }
    
    public VerifyInfo verify (InputStream pdfIS) throws Exception {
        VerifyInfo verifyInfo = new VerifyInfo ();    
        
        PdfReader reader = new PdfReader(pdfIS);
        AcroFields acroFields = reader.getAcroFields();
        ArrayList names = acroFields.getSignatureNames();
        for (Iterator it = names.iterator(); it.hasNext();) {
            String name = (String) it.next();   
            logger.info (String.format("Signature name:%s", name));
            logger.info (String.format("Signature covers whole document:%b", acroFields.signatureCoversWholeDocument(name)));    
            logger.info (String.format("Document revision: %s of %d", acroFields.getRevision(name), acroFields.getTotalRevisions()));                                     
            
            PdfPKCS7 pk = acroFields.verifySignature(name);
            if (pk.verify() == true) {

                // create signer informations                
                SignerInfo signerInfo = new SignerInfo ();
                signerInfo.setAuthor(DNParser.parse(pk.getSigningCertificate().getSubjectDN().toString(), "CN"));
                signerInfo.setDateSign(pk.getSignDate().getTime());
                signerInfo.setCounterSignature(false);
                                 
                PdfDictionary dic = acroFields.getSignatureDictionary(name);   
                CMSSignedData signedData = new CMSSignedData (dic.get(PdfName.CONTENTS).getBytes());
                Iterator iter = signedData.getSignerInfos().getSigners().iterator();
                SignerInformation si = (SignerInformation)iter.next();                
                signerInfo.setSignerInformation(si);  
                signerInfo.setX509Cert(pk.getSigningCertificate());
                signerInfo.setLevel(0);               
                
                // check signed type
                if (si.getSignedAttributes() != null && si.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) != null) {
                    signerInfo.setSignType(SignType.PAdES_BES); 
                    if (si.getUnsignedAttributes() != null && si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
                        signerInfo.setSignType(SignType.PAdES_T);                        
                        if (si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs) != null &&
                            si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs) != null) {
                            signerInfo.setSignType(SignType.PAdES_C);
                        }
                    }                    
                }
                else {
                    signerInfo.setSignType(SignType.PDF);
                }                                 
                verifyInfo.addSignerInfo(signerInfo);
            
                // validate certificate
                if (Boolean.valueOf(getProperty(VerifyCertificate.getLiteral()))) {
                    validateCertificate(signerInfo);
                }               
                
                logger.info ("Verified!");  
                logger.info (String.format("SignType:%s", signerInfo.getSignType()));                  
                logger.info (String.format("DateSign:%s", new SimpleDateFormat("dd-MM-yyyy hh:mm:ss").format(signerInfo.getDateSign()))); 
                logger.info (String.format("Author:%s", signerInfo.getAuthor()));  
                logger.info (String.format("isCounterSignature:%b", signerInfo.isCounterSignature()));                  
            }
            else {
                logger.fatal (String.format("Sign %s not verified", name));                
                throw new Exception (String.format("Sign %s not verified", name));            
            }
        }
        
        return verifyInfo;
    } 
    
    public static void main (String []args) throws Exception {
        DOMConfigurator.configure("log4j.xml");
        Properties prop = new Properties ();      
        PdfVerify pdfVerify = new PdfVerify (prop);
        
        FileInputStream fis = null;
        
        try {
            fis = new FileInputStream ("libre_sign.pdf");
            VerifyInfo vi = pdfVerify.verify(fis);            
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
        }
        
    }    
}
