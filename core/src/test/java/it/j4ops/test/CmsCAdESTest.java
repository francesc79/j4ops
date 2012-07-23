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
public class CmsCAdESTest extends TestCase {
    private Properties prop = new Properties ();
    private SignProvider signProvider = null;     
    private SignHandler signHandler = null;    
    
    public CmsCAdESTest () throws Exception {
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
    
    public void testSignCAdES () throws Exception {
        // set property       
        CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop);        
        
        // sign
        FileInputStream fis = new FileInputStream ("modena.pdf");      
        FileOutputStream fos = new FileOutputStream ("./test/CAdES/sign.p7m");                     
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
    
    public void testAddSignCAdES () throws Exception {
        // set property      
        CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop);        
        
        // add sign
        FileInputStream fis = new FileInputStream ("./test/CAdES/sign.p7m");      
        FileOutputStream fos = new FileOutputStream ("./test/CAdES/add_sign.p7m");                            
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
    
    public void testCounterSignCAdES () throws Exception {
        // set property   
        CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop);        
        
        // counter sign
        FileInputStream fis = new FileInputStream ("./test/CAdES/sign.p7m");      
        FileOutputStream fos = new FileOutputStream ("./test/CAdES/counter_sign.p7m");                     
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
    
    
    public void testVerifySignCAdES () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/CAdES/sign.p7m");
        FileOutputStream fos = new FileOutputStream ("./test/CAdES/sign_verified.pdf");    
        CmsVerify p7xVerify = new CmsVerify (new Properties ());        
        VerifyInfo vi = p7xVerify.verify(fis, null, fos);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 1 || vi.getSignerInfos().get(0).getSignType() != SignType.CAdES_BES) {
            throw new Exception ("Error on verify sign CAdES");
        }
    }
    
    public void testVerifyAddSignCAdES () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/CAdES/add_sign.p7m");
        FileOutputStream fos = new FileOutputStream ("./test/CAdES/sign_verified.pdf");    
        CmsVerify p7xVerify = new CmsVerify (new Properties ());        
        VerifyInfo vi = p7xVerify.verify(fis, null, fos);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 2 || 
            vi.getSignerInfos().get(0).getSignType() != SignType.CAdES_BES ||
            vi.getSignerInfos().get(1).getSignType() != SignType.CAdES_BES) {
            throw new Exception ("Error on verify sign CAdES");
        }
    }   
    
    public void testVerifyCounterSignCAdES () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/CAdES/counter_sign.p7m");
        FileOutputStream fos = new FileOutputStream ("./test/CAdES/sign_verified.pdf");    
        CmsVerify p7xVerify = new CmsVerify (new Properties ());        
        VerifyInfo vi = p7xVerify.verify(fis, null, fos);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 1 || 
            vi.getSignerInfos().get(0).getSignType() != SignType.CAdES_BES ||
            vi.getSignerInfos().get(0).getSignerInfos().isEmpty() ||
            vi.getSignerInfos().get(0).getSignerInfos().get(0).getSignType() != SignType.CAdES_BES ||
            !vi.getSignerInfos().get(0).getSignerInfos().get(0).isCounterSignature()) {
            throw new Exception ("Error on verify sign CAdES");
        }
    }     
    
    
    @Override
    protected void setUp() {
        DOMConfigurator.configure("log4j.xml");
        new File("./test/CAdES/").mkdirs();
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
        TestRunner.run(CmsCAdESTest.class);
    }
}
