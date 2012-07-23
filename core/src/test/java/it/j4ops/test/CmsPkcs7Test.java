/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.test;

import it.j4ops.CmsSignMode;
import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import it.j4ops.sign.BaseSignHandler;
import it.j4ops.sign.CmsSign;
import it.j4ops.sign.SignHandler;
import it.j4ops.sign.provider.PKCS12Provider;
import it.j4ops.sign.provider.SignProvider;
import it.j4ops.verify.CmsVerify;
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
public class CmsPkcs7Test extends TestCase {
    private Properties prop = new Properties ();
    private SignProvider signProvider = null;     
    private SignHandler signHandler = null;    
    
    public CmsPkcs7Test () throws Exception {
        signHandler = new BaseSignHandler("sign");            
        signProvider = new PKCS12Provider("j4ops.p12");   
        
        prop.setProperty(DigestAlgName.getLiteral(), "SHA256"); 
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "CAdES_BES");
        prop.setProperty(EnvelopeEncode.getLiteral(), "B64");        
        prop.setProperty(TSAURL.getLiteral(), "http://dse200.ncipher.com/TSS/HttpTspServer");        
        prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "testCA.ks"); 
        prop.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");        
    }
    
    public void testSignPkcs7 () throws Exception {
        // set property
        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "Pkcs7");        
        CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop);        
        
        // sign
        FileInputStream fis = new FileInputStream ("modena.pdf");      
        FileOutputStream fos = new FileOutputStream ("./test/Pkcs7/sign.p7m");                     
        try {
            cmsSign.init();
            cmsSign.sign(new Date(), CmsSignMode.Attached, fis, fos);
        }
        finally {
            cmsSign.destroy();
        } 
        fis.close();
        fos.close();           
    }
    
    public void testAddSignPkcs7 () throws Exception {
        // set property
        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "Pkcs7");        
        CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop);        
        
        // add sign
        FileInputStream fis = new FileInputStream ("./test/Pkcs7/sign.p7m");      
        FileOutputStream fos = new FileOutputStream ("./test/Pkcs7/add_sign.p7m");                     
        try {
            cmsSign.init();
            cmsSign.addSign(new Date(), CmsSignMode.Attached, fis, fos);
        }
        finally {
            cmsSign.destroy();
        }  
        fis.close();
        fos.close();           
    }    
    
    public void testCounterSignPkcs7 () throws Exception {
        // set property
        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "Pkcs7");        
        CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop);        
        
        // counter sign
        FileInputStream fis = new FileInputStream ("./test/Pkcs7/sign.p7m");      
        FileOutputStream fos = new FileOutputStream ("./test/Pkcs7/counter_sign.p7m");                     
        try {
            cmsSign.init();
            cmsSign.counterSign(new Date(), CmsSignMode.Attached, fis, fos);
        }
        finally {
            cmsSign.destroy();
        } 
        fis.close();
        fos.close();           
    }       
    
    
    public void testVerifySignPkcs7 () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/Pkcs7/sign.p7m");
        FileOutputStream fos = new FileOutputStream ("./test/Pkcs7/sign_verified.pdf");    
        CmsVerify p7xVerify = new CmsVerify (new Properties ());        
        VerifyInfo vi = p7xVerify.verify(fis, null, fos);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 1 || vi.getSignerInfos().get(0).getSignType() != SignType.Pkcs7) {
            throw new Exception ("Error on verify sign Pkcs7");
        }
    }
    
    public void testVerifyAddSignPkcs7 () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/Pkcs7/add_sign.p7m");
        FileOutputStream fos = new FileOutputStream ("./test/Pkcs7/sign_verified.pdf");    
        CmsVerify p7xVerify = new CmsVerify (new Properties ());        
        VerifyInfo vi = p7xVerify.verify(fis, null, fos);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 2 || 
            vi.getSignerInfos().get(0).getSignType() != SignType.Pkcs7 ||
            vi.getSignerInfos().get(1).getSignType() != SignType.Pkcs7) {
            throw new Exception ("Error on verify sign Pkcs7");
        }
    }   
    
    public void testVerifyCounterSignPkcs7 () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/Pkcs7/counter_sign.p7m");
        FileOutputStream fos = new FileOutputStream ("./test/Pkcs7/sign_verified.pdf");    
        CmsVerify p7xVerify = new CmsVerify (new Properties ());        
        VerifyInfo vi = p7xVerify.verify(fis, null, fos);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 1 || 
            vi.getSignerInfos().get(0).getSignType() != SignType.Pkcs7 ||
            vi.getSignerInfos().get(0).getSignerInfos().isEmpty() ||
            vi.getSignerInfos().get(0).getSignerInfos().get(0).getSignType() != SignType.Pkcs7 ||
            !vi.getSignerInfos().get(0).getSignerInfos().get(0).isCounterSignature()) {
            throw new Exception ("Error on verify sign Pkcs7");
        }
    }     
    
    
    @Override
    protected void setUp() {
        DOMConfigurator.configure("log4j.xml");
        new File("./test/Pkcs7/").mkdirs();
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
        TestRunner.run(CmsPkcs7Test.class);
    }    
}
