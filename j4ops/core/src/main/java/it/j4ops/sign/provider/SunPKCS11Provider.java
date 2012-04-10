/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign.provider;

import it.j4ops.util.HexString;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import org.apache.log4j.Logger;
import sun.security.pkcs11.SunPKCS11;

/**
 *
 * @author fzanutto
 */
public class SunPKCS11Provider extends PKCS11Provider {  
    
    private Logger logger = Logger.getLogger(this.getClass());    
    private KeyStore caKs;    
    private boolean flagInit = false; 
    private String algorithm = null;
    private KeyIDAndX509Cert selectKeyIDAndCertificate;       
    private SunPKCS11 sunPKCS11 = null;
    
    public SunPKCS11Provider(String tokensConfig) {
        super(tokensConfig);        
    }    
    
    @Override
    public void init(String digestAlgName, String encryptionAlgName, SignProviderHandler handlerProvider, String securityProvider) throws Exception {

        // init token
        super.init(digestAlgName, encryptionAlgName, handlerProvider, securityProvider);        
        
        // config Sun PKCS11 provider
        String config = null;
        if (getTokenInfo().getSlotID() >= 0) {
            config = String.format("name=SmartCard-%02d\nlibrary=%s\nshowInfo=%s\nslot=%d\n", 
                                    getTokenInfo().getSlotID(), getTokenInfo().getDriver(), true, getTokenInfo().getSlotID());            
        }
        else {
            config = String.format("name=SmartCard-00\nlibrary=%s\nshowInfo=%s\n", getTokenInfo().getDriver(), true);              
        }
        logger.info("SunPKCS11 config:" + config);
        
        // create Sun PKCS11 provider        
        ByteArrayInputStream bais = null;
        try {
            bais = new ByteArrayInputStream(config.getBytes());
            sunPKCS11 = new SunPKCS11 (bais); 
        }
        finally {
            try {
                if (bais != null) {
                    bais.close();
                    bais = null;
                }
            }
            catch (Exception ex) {}
        }
                        
        // get algorithm
        algorithm = String.format ("%swith%s", digestAlgName, encryptionAlgName);          
        
        // check if the provider is in use
        if (Security.getProvider(sunPKCS11.getName()) != null) {
            throw new Exception (String.format("Provider %s busy", sunPKCS11.getName()));
        }        
        logger.debug("add PKCS11 provider " + sunPKCS11.getName());
        Security.addProvider(sunPKCS11); 
        
        // istance key store
        caKs = KeyStore.getInstance("PKCS11");
        if (caKs == null) {
            throw new Exception ("no generate PKCS11 keystore");
        }
        
        // get pin
        String pin = handlerProvider.getPassword();        
        
        // load key store
        caKs.load (null, pin.toCharArray()); 
        
        ArrayList<KeyIDAndX509Cert> lstKeyAndX509Cert = new ArrayList<KeyIDAndX509Cert>();
        Enumeration<String> enumer = caKs.aliases();
        while (enumer.hasMoreElements()) {
            String alias = enumer.nextElement();
            logger.info("alias found:" + alias); 
            
            Certificate[] chain = caKs.getCertificateChain(alias);
            if (chain != null && chain.length > 0) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate x509Cert = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(chain[0].getEncoded()));             
                
                KeyIDAndX509Cert keyIDAndX509Cert = new KeyIDAndX509Cert();
                keyIDAndX509Cert.setKeyID(alias.getBytes());
                keyIDAndX509Cert.setX509Cert(x509Cert);
                keyIDAndX509Cert.setCertLabel(alias);
                lstKeyAndX509Cert.add(keyIDAndX509Cert);
            }                
        }
        
        // select witch certificate you use
        selectKeyIDAndCertificate = handlerProvider.selectKeyIDAndX509Cert(lstKeyAndX509Cert);        
        
        if (selectKeyIDAndCertificate == null) {
            throw new Exception("No selected certificate");
        }        
        
        // provider is initialized
        flagInit = true;           
    }
    
    private PrivateKey getPrivateKey (byte []keyID) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return (PrivateKey)caKs.getKey(new String(keyID), null);        
    }    

    @Override
    public void destroy() throws Exception {
        if (sunPKCS11 != null) {
            logger.debug("remove PKCS11 provider " + sunPKCS11.getName());
            if (Security.getProvider(sunPKCS11.getName()) != null) {
                Security.removeProvider(sunPKCS11.getName());
            }
        }
        flagInit = false;        
    }

    @Override
    public byte[] sign(byte[] toEncrypt) throws Exception {
        
        // check if init provider
        if (flagInit == false) {
            throw new Exception ("Provider not initialized");
        }
        
        // get private key
        PrivateKey privateKey = getPrivateKey (selectKeyIDAndCertificate.getKeyID());          
        
        // signing
        Signature sig = Signature.getInstance(algorithm, sunPKCS11);
        sig.initSign(privateKey);
        
        logger.info("data to sign:" + HexString.hexify(toEncrypt));
        
        sig.update(toEncrypt);        
        byte [] signature = sig.sign();
                
        logger.info("data signed:" + HexString.hexify(signature)); 
        
        return signature;
    }

    @Override
    public X509Certificate getX509Certificate() {
        assert null != selectKeyIDAndCertificate;
        return selectKeyIDAndCertificate.getX509Cert();
    } 
    
    @Override    
    public String getCertLabel () {
        assert null != selectKeyIDAndCertificate;
        return selectKeyIDAndCertificate.getCertLabel();        
    }
    
    @Override
    public String toString () {
        return "SunPKCS11";
    }     
}
