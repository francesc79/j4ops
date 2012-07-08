/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign.provider;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;
import it.j4ops.util.HexString;
import it.j4ops.util.IaikUtil;
import it.j4ops.util.NativeLibLoader;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.apache.log4j.Logger;


/**
 *
 * @author fzanutto
 */
public class IaikPKCS11Provider extends PKCS11Provider {
    private static Logger logger = Logger.getLogger (IaikPKCS11Provider.class); 
    private KeyIDAndX509Cert selectKeyIDAndCertificate;    

    private Mechanism mechanismSignAlgId = null;
    private Module pkcs11Module = null;
    private Session session = null;
    private boolean flagInit = false;
    
	static {
        try {
            System.loadLibrary("pkcs11wrapper");
        } catch (UnsatisfiedLinkError e) {
            try {
				NativeLibLoader.loadLib ("", "/libpkcs11wrapper");
			} catch (Exception ex) {
				logger.fatal(ex.getMessage(), ex);
			}
        }
	}        
    
    public IaikPKCS11Provider(String tokensConfig) {
        super(tokensConfig);        
    }  
    
    @Override
    public void init (String digestAlgName, String encryptionAlgName, SignProviderHandler handlerProvider, String securityProvider) throws Exception {   
        long algId = CKM_SHA256_RSA_PKCS;
        
        // init token
        super.init(digestAlgName, encryptionAlgName, handlerProvider, securityProvider);
        
        // get algorithm
        if ("RSA".equals(encryptionAlgName)) {
            if ("SHA1".equals(digestAlgName)) {
                algId = CKM_SHA1_RSA_PKCS;
            }
            else if ("SHA256".equals(digestAlgName)) {
                algId = CKM_SHA256_RSA_PKCS;
            }
            else if ("SHA384".equals(digestAlgName)) {
                algId = CKM_SHA384_RSA_PKCS;
            }     
            else if ("SHA512".equals(digestAlgName)) {
                algId = CKM_SHA512_RSA_PKCS;
            }         
            else {
                algId = CKM_RSA_PKCS;
            }
        }
        else if ("DSA".equals(encryptionAlgName)) {
            if ("SHA1".equals(digestAlgName)) {
                algId = CKM_DSA_SHA1;
            }                    
        }
        logger.debug(String.format("algId %d", algId));
        mechanismSignAlgId = Mechanism.get(algId);
        
        // get module
        pkcs11Module = Module.getInstance(getTokenInfo().getDriver());
        pkcs11Module.initialize(null);            

        // select token
        Token token = null;
        if (getTokenInfo().getSlotID() >= 0) {
            token = IaikUtil.selectToken(pkcs11Module, getTokenInfo().getSlotID());
        }
        else {
            token = IaikUtil.selectToken(pkcs11Module);
        }
        if (token == null) {
            throw new Exception("No token to proceed.");
        }
        logger.info (String.format("Token ID %s Info %s", token.getTokenID(), token.getTokenInfo()));

        // select mechanism
        List supportedMechanisms = Arrays.asList(token.getMechanismList());
        if (!supportedMechanisms.contains(mechanismSignAlgId)) {
            throw new Exception(String.format("This token does not support raw %s signing!", mechanismSignAlgId));
        } else {
            MechanismInfo rsaMechanismInfo = token.getMechanismInfo(mechanismSignAlgId);
            if (!rsaMechanismInfo.isSign()) {
                throw new Exception(String.format("This token does not support %s signing according to PKCS!", mechanismSignAlgId));
            }
        }
        
        // get pin
        String pin = handlerProvider.getPassword();

        // open session with device
        session = IaikUtil.openAuthorizedSession(token, Token.SessionReadWriteBehavior.RO_SESSION, pin);

        // get all certificates
        List<KeyIDAndX509Cert> lstKeyAndX509Cert = IaikUtil.getCertificates(session, securityProvider);
        
        // select witch certificate you use
        selectKeyIDAndCertificate = handlerProvider.selectKeyIDAndX509Cert(lstKeyAndX509Cert);

        if (selectKeyIDAndCertificate == null) {
            throw new Exception("No selected certificate");
        }

        // provider is initialized
        flagInit = true;
    }
    
    @Override
    public void destroy () throws Exception {
        if (session != null) {
            session.closeSession();
            session = null;
        }
        if (pkcs11Module != null) {
            pkcs11Module.finalize(null);        
        }        
        flagInit = false;
    }    
    
    @Override
    public byte [] sign(byte[] toEncrypt) throws Exception {
        
        // check if init provider
        if (flagInit == false) {
            throw new Exception ("Provider not initialized");
        }        
        logger.info("KeyID:" + HexString.hexify(selectKeyIDAndCertificate.getKeyID()));        
        
        // get private key
        RSAPrivateKey keyTemplate = new RSAPrivateKey();
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);        
        PrivateKey selectedSignatureKey = IaikUtil.getPrivateKey(session, keyTemplate, selectKeyIDAndCertificate.getKeyID());
        if (selectedSignatureKey == null) {
            throw new Exception ("No key retrieve");
        }
        
        // initialize for signing
        session.signInit(mechanismSignAlgId, selectedSignatureKey);         

        logger.info("data to sign:" + HexString.hexify(toEncrypt));

        // sign the data to be signed        
        byte [] signature = session.sign(toEncrypt);
        
        logger.info("data signed:" + HexString.hexify(signature));        
        
        return signature;
    }
    
    @Override
    public X509Certificate getX509Certificate () {
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
        return "IaikPKCS11";
    }    
}
