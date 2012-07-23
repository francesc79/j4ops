/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.test;

import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import it.j4ops.sign.BaseSignHandler;
import it.j4ops.sign.PdfSign;
import it.j4ops.sign.SignHandler;
import it.j4ops.sign.provider.PKCS12Provider;
import it.j4ops.sign.provider.SignProvider;
import it.j4ops.verify.PdfVerify;
import it.j4ops.verify.bean.VerifyInfo;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Date;
import java.util.Properties;
import junit.framework.TestCase;
import junit.swingui.TestRunner;
import org.apache.log4j.xml.DOMConfigurator;

/**
 *
 * @author fzanutto
 */
public class PdfPAdESTest extends TestCase {
    private Properties prop = new Properties ();
    private SignProvider signProvider = null;     
    private SignHandler signHandler = null;    
    
    public PdfPAdESTest () throws Exception {
        signHandler = new BaseSignHandler("sign");            
        signProvider = new PKCS12Provider("j4ops.p12");   
        
        prop.setProperty(DigestAlgName.getLiteral(), "SHA256"); 
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "PAdES_BES");      
        prop.setProperty(TSAURL.getLiteral(), "http://dse200.ncipher.com/TSS/HttpTspServer");        
        prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "testCA.ks"); 
        prop.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");        
    }
    
    public void testSignPAdES () throws Exception {
        // set property     
        PdfSign pdfSign = new PdfSign (signProvider, signHandler, prop);        
        
        // sign
        FileInputStream fis = new FileInputStream ("modena.pdf");      
        FileOutputStream fos = new FileOutputStream ("./test/PAdES/sign.pdf");                     
        try {
            pdfSign.init();
            pdfSign.sign(new Date(), fis, null, fos);
        }
        finally {
            pdfSign.destroy();
        }  
        fis.close();
        fos.close();           
    }
    
    public void testAddSignPAdES () throws Exception {
        // set property     
        PdfSign pdfSign = new PdfSign (signProvider, signHandler, prop);             
        
        // add sign
        FileInputStream fis = new FileInputStream ("./test/PAdES/sign.pdf");      
        FileOutputStream fos = new FileOutputStream ("./test/PAdES/add_sign.pdf");                     
        try {
            pdfSign.init();
            pdfSign.addSign(new Date(), fis, null, fos);
        }
        finally {
            pdfSign.destroy();
        }          
        fis.close();
        fos.close();           
    }    
    
    public void testVerifySignPAdES () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/PAdES/sign.pdf");    
        PdfVerify pdfVerify = new PdfVerify (new Properties ());        
        VerifyInfo vi = pdfVerify.verify(fis);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 1 || vi.getSignerInfos().get(0).getSignType() != SignType.PAdES_BES) {
            throw new Exception ("Error on verify sign PAdES");
        }
    }
    
    public void testVerifyAddSignPAdES () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/PAdES/add_sign.pdf");   
        PdfVerify pdfVerify = new PdfVerify (new Properties ());        
        VerifyInfo vi = pdfVerify.verify(fis);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 2 || 
            vi.getSignerInfos().get(0).getSignType() != SignType.PAdES_BES ||
            vi.getSignerInfos().get(1).getSignType() != SignType.PAdES_BES) {
            throw new Exception ("Error on verify sign PAdES");
        }
    }       

    
    @Override
    protected void setUp() {
        DOMConfigurator.configure("log4j.xml");
        new File("./test/PAdES/").mkdirs();
    }        

    @Override
    public void tearDown() {
    }


    /**
     * Test
     * @param args null
     * @throws Exception in caso di errore
     */
    public static void main(String[] args) throws Exception {
        TestRunner.run(PdfPDFTest.class);
    }    
}

