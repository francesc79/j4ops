/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign.provider;

import it.j4ops.util.HexString;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import org.apache.log4j.Logger;

/**
 *
 * @author fzanutto
 */
public class PKCS12Provider implements SignProvider {    
    
    private Logger logger = Logger.getLogger(this.getClass());    
    private String ketStoreFile;    
    private KeyStore caKs;
    private String password;
    private boolean flagInit = false; 
    private String algorithm = null;
    private String securityProvider;
    private KeyIDAndX509Cert selectKeyIDAndCertificate;      
    
    public PKCS12Provider (String ketStoreFile) {
        this.ketStoreFile = ketStoreFile;
    }    
    
    public void setKetStoreFile (String ketStoreFile) {
        this.ketStoreFile = ketStoreFile;
    }    
    
    private PrivateKey getPrivateKey (byte []keyID) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        assert null != password;
        return (PrivateKey)caKs.getKey(new String(keyID), password.toCharArray());        
    }
    
    @Override
    public void init(String digestAlgName, String encryptionAlgName, SignProviderHandler handlerProvider, String securityProvider) throws Exception {
        
        // get algorithm
        algorithm = String.format ("%swith%s", digestAlgName, encryptionAlgName);     
        this.securityProvider = securityProvider;
        
        // get password
        password = handlerProvider.getPassword();        
        
        // load keystore
        caKs = KeyStore.getInstance("PKCS12");
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(ketStoreFile);
            caKs.load(fis, password.toCharArray());
        }
        finally {
            if (fis != null) {
                fis.close();
                fis = null;
            }
        }

        // load certificates
        ArrayList<KeyIDAndX509Cert> lstKeyAndX509Cert = new ArrayList<KeyIDAndX509Cert>();
        Enumeration<String> enumer = caKs.aliases();
        while (enumer.hasMoreElements()) {
            String alias = enumer.nextElement();
            logger.info("alias found:" + alias); 
            
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate[] certs = caKs.getCertificateChain(alias);
            if (certs != null && certs.length > 0) {
                for (int index = 0; index < certs.length; index ++) {                    
                    X509Certificate x509Cert = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(certs[index].getEncoded()));             
                    logger.info(String.format("add certificate serial number: %d", x509Cert.getSerialNumber()));                    
                    KeyIDAndX509Cert keyIDAndX509Cert = new KeyIDAndX509Cert();
                    keyIDAndX509Cert.setKeyID(alias.getBytes());
                    keyIDAndX509Cert.setX509Cert(x509Cert);
                    keyIDAndX509Cert.setCertLabel(alias);                    
                    if (!lstKeyAndX509Cert.contains(keyIDAndX509Cert)) {
                        lstKeyAndX509Cert.add(keyIDAndX509Cert);
                    }
                }
            }     

            Certificate cert = caKs.getCertificate(alias);
            if (cert != null) {
                X509Certificate x509Cert = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));             
                logger.info(String.format("add certificate serial number: %d", x509Cert.getSerialNumber()));
                KeyIDAndX509Cert keyIDAndX509Cert = new KeyIDAndX509Cert();
                keyIDAndX509Cert.setKeyID(alias.getBytes());
                keyIDAndX509Cert.setX509Cert(x509Cert);
                keyIDAndX509Cert.setCertLabel(alias);
                if (!lstKeyAndX509Cert.contains(keyIDAndX509Cert)) {
                    lstKeyAndX509Cert.add(keyIDAndX509Cert);
                }          
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

    @Override
    public void destroy() throws Exception {
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
        
        // get signature istance
        Signature sig = Signature.getInstance(algorithm, securityProvider); 
        sig.initSign(privateKey);
        
        logger.info("data to sign:" + HexString.hexify(toEncrypt));        
        
        // sign date
        sig.update(toEncrypt);        
        byte [] signature = sig.sign();
        
        logger.info("signed data:" + HexString.hexify(signature));                
        
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
        return "PKCS12";
    }
}
