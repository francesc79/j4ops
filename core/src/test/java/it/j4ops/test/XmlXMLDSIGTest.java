/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.test;

import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import it.j4ops.XmlSignMode;
import it.j4ops.sign.BaseSignHandler;
import it.j4ops.sign.SignHandler;
import it.j4ops.sign.XmlSign;
import it.j4ops.sign.provider.PKCS12Provider;
import it.j4ops.sign.provider.SignProvider;
import it.j4ops.verify.XmlVerify;
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
public class XmlXMLDSIGTest extends TestCase {
    private Properties prop = new Properties ();
    private SignProvider signProvider = null;     
    private SignHandler signHandler = null;    
    
    public XmlXMLDSIGTest () throws Exception {
        signHandler = new BaseSignHandler("sign");            
        signProvider = new PKCS12Provider("j4ops.p12");   
        
        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "XMLDSIG");      
        prop.setProperty(TSAURL.getLiteral(), "http://dse200.ncipher.com/TSS/HttpTspServer"); 
        prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "testCA.ks"); 
        prop.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");        
    }
    
    public void testSignXMLDSIG () throws Exception {
        // set property     
        XmlSign xmlSign = new XmlSign (signProvider, signHandler, prop);        
        
        // sign
        File f = new File ("prova.xml");
        FileInputStream fis = new FileInputStream (f);          
        FileOutputStream fos = new FileOutputStream ("./test/XMLDSIG/sign.xml");                     
        try {
            xmlSign.init();
            xmlSign.sign(new Date(), XmlSignMode.Enveloped, f.toURI().toURL().toString(), fis, fos);
        }
        finally {
            xmlSign.destroy();
        }
        fis.close();
        fos.close();           
    }
    
    public void testAddSignXMLDSIG () throws Exception {
        // set property     
        XmlSign xmlSign = new XmlSign (signProvider, signHandler, prop);          
        
        // add sign
        File f = new File ("./test/XMLDSIG/sign.xml");
        FileInputStream fis = new FileInputStream (f);          
        FileOutputStream fos = new FileOutputStream ("./test/XMLDSIG/add_sign.xml");                     
        try {
            xmlSign.init();
            xmlSign.addSign(new Date(), XmlSignMode.Enveloped, f.toURI().toURL().toString(), fis, fos);
        }
        finally {
            xmlSign.destroy();
        }
        fis.close();
        fos.close();           
    }    
    
    public void testVerifySignXMLDSIG () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/XMLDSIG/sign.xml");    
        XmlVerify xmlVerify = new XmlVerify (new Properties ());        
        VerifyInfo vi = xmlVerify.verify(fis);          
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 1 || vi.getSignerInfos().get(0).getSignType() != SignType.XMLDSIG) {
            throw new Exception ("Error on verify sign XMLDSIG");
        }
    }
    
    public void testVerifyAddSignXMLDSIG () throws Exception { 
        FileInputStream fis = new FileInputStream ("./test/XMLDSIG/add_sign.xml");   
        XmlVerify xmlVerify = new XmlVerify (new Properties ());        
        VerifyInfo vi = xmlVerify.verify(fis);            
        System.out.println (String.format("count signs:%d", vi.getCountSigns()));   
        
        if (vi.getCountSigns() != 2 || 
            vi.getSignerInfos().get(0).getSignType() != SignType.XMLDSIG ||
            vi.getSignerInfos().get(1).getSignType() != SignType.XMLDSIG) {
            throw new Exception ("Error on verify sign XMLDSIG");
        }
    }       

    
    @Override
    protected void setUp() {
        DOMConfigurator.configure("log4j.xml");
        new File("./test/XMLDSIG/").mkdirs();
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
        TestRunner.run(XmlXMLDSIGTest.class);
    }    
}
