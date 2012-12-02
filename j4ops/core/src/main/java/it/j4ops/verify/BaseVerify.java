/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.verify;

import static it.j4ops.PropertyConstants.*;
import it.j4ops.util.CRLVerifier;
import it.j4ops.util.X509Util;
import it.j4ops.verify.bean.SignerInfo;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author fzanutto
 */
public abstract class BaseVerify {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private Properties properties;    
    
    public BaseVerify (Properties prop) {
        
        properties = new Properties(getDefault());
        Set set = prop.entrySet();
        Iterator it = set.iterator();
        while (it.hasNext()) {
        Map.Entry entry = (Map.Entry) it.next();
            properties.setProperty((String)entry.getKey(), (String)entry.getValue());
        } 
        
        // check if add security provider
        if (BouncyCastleProvider.PROVIDER_NAME.equals(properties.getProperty(SecurityProvider.getLiteral())) && 
            Security.getProvider(properties.getProperty(SecurityProvider.getLiteral())) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }    
    
    private Properties getDefault () {
        Properties defaultProp = new Properties ();
        defaultProp.setProperty(SecurityProvider.getLiteral(), BouncyCastleProvider.PROVIDER_NAME);  
        defaultProp.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "certs.ks");   
        defaultProp.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");       
        defaultProp.setProperty(VerifyCRL.getLiteral(), "true");   
        defaultProp.setProperty(VerifyCertificate.getLiteral(), "true");            
        return defaultProp;
    }
    
    public String getProperty(String key) {
        return properties.getProperty(key);
    }    
    
    public Properties getProperties() {
        return properties;
    } 
    
    protected void validateCertificate (SignerInfo signerInfo) throws Exception {
        logger.debug("loading ca trusted certificates from " + getProperty(FileKeyStoreTrustedRootCerts.getLiteral()));
        Set<X509Certificate> trustedCerts =  X509Util.loadKeyStore(getProperty(FileKeyStoreTrustedRootCerts.getLiteral()),
                                                                   getProperty(PassKeyStoreTrustedRootCerts.getLiteral()));
        logger.debug(String.format("loaded %d ca trusted certificates", trustedCerts.size())); 
        X509Util.validateChain(signerInfo.getX509Cert(), trustedCerts, getProperty(SecurityProvider.getLiteral()));
        
        // check if verify CRL
        if (Boolean.valueOf(getProperty(VerifyCRL.getLiteral()))) {
            CRLVerifier.verifyCertificateCRLs(signerInfo.getX509Cert());
        }        
    }   
   
}
