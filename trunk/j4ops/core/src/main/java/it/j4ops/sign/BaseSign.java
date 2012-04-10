/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign;


import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import it.j4ops.sign.cms.ExternalSignerInfoGenerator;
import it.j4ops.sign.provider.SignProvider;
import it.j4ops.util.CRLVerifier;
import it.j4ops.util.TimeStampTokenUtil;
import it.j4ops.util.X509Util;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;

/**
 *
 * @author fzanutto
 */
public abstract class BaseSign implements Sign {
    private Logger logger = Logger.getLogger(this.getClass()); 
    
    private SignHandler signHandler;    
    private SignProvider signProvider;
    private Properties properties;  
    private List<X509Certificate> certificateChain;
    private boolean initialized = false;
    
    public BaseSign (SignProvider signProvider, SignHandler signHandler, Properties prop) {
        this.signProvider = signProvider;
        this.signHandler = signHandler;
        
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
            logger.debug("Add bouncy castle provider");
        }
    }
    
    private Properties getDefault () {
        Properties defaultProp = new Properties ();
        defaultProp.setProperty(SecurityProvider.getLiteral(), BouncyCastleProvider.PROVIDER_NAME);                 
        defaultProp.setProperty(DigestAlgName.getLiteral(), "SHA256");
        defaultProp.setProperty(EncryptionAlgName.getLiteral(), "RSA");
        defaultProp.setProperty(EnvelopeEncode.getLiteral(), "DER");
        defaultProp.setProperty(EnvelopeSignType.getLiteral(), SignType.PAdES_BES.getLiteral());             
        defaultProp.setProperty(TSAURL.getLiteral(), "http://timestamping.edelweb.fr/service/tsp");
        defaultProp.setProperty(TSAUser.getLiteral(), ""); 
        defaultProp.setProperty(TSAPassword.getLiteral(), ""); 
        defaultProp.setProperty(VerifyCRL.getLiteral(), "false");
        defaultProp.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "certs.ks");   
        defaultProp.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");            
        return defaultProp;    
    }

    public String getProperty(String key) {
        return properties.getProperty(key);
    }    
    
    public void setProperty(String key, String value) {
        properties.setProperty(key, value);
    }       
    
    public Properties getProperties() {
        return properties;
    }
    
    public String getDigestAlgOID () {
        return ExternalSignerInfoGenerator.getOIDFromDigestAlgName(getProperty(DigestAlgName.getLiteral()));
    }

    public String getEncryptionAlgOID () {
        return ExternalSignerInfoGenerator.getOIDFromEncryptionAlgName(getProperty(EncryptionAlgName.getLiteral()));
    }
    
    public SignType getEnvelopeSignType () {
        return SignType.valueOf(getProperty(EnvelopeSignType.getLiteral()));
    }    
    
    public SignProvider getSignProvider () {
        return signProvider;
    }

    public SignHandler getSignHandler() {
        return signHandler;
    }
    
    protected List<X509Certificate> buildAndValidateChain (X509Certificate x509Cert) throws Exception {
        logger.debug("loading ca trusted certificates from " + getProperty(FileKeyStoreTrustedRootCerts.getLiteral()));
        Set<X509Certificate> trustedCerts =  X509Util.loadKeyStore(getProperty(FileKeyStoreTrustedRootCerts.getLiteral()),
                                                                   getProperty(PassKeyStoreTrustedRootCerts.getLiteral()));
        logger.debug(String.format("loaded %d ca trusted certificates", trustedCerts.size())); 
        return X509Util.buildAndValidateChain(x509Cert, trustedCerts, getProperty(SecurityProvider.getLiteral()));
    } 
    
    protected void validateTimeStampToken (TimeStampToken timeStampToken) throws Exception {
        logger.debug("loading ca trusted certificates from " + getProperty(FileKeyStoreTrustedRootCerts.getLiteral()));
        Set<X509Certificate> trustedCerts =  X509Util.loadKeyStore(getProperty(FileKeyStoreTrustedRootCerts.getLiteral()),
                                                                   getProperty(PassKeyStoreTrustedRootCerts.getLiteral()));
        logger.debug(String.format("loaded %d ca trusted certificates", trustedCerts.size()));         
        TimeStampTokenUtil.validateTimeStampToken(timeStampToken, trustedCerts, getProperty(SecurityProvider.getLiteral()));
    }     

    @Override
    public X509Certificate init () throws Exception {
        
        // check if alredy initialized
        if (initialized == true) {
            throw new Exception ("already initialized");
        }

        // sign provider initialization
        switch (getEnvelopeSignType()) {        
            case PDF:   
            case PAdES_BES:     
            case PAdES_T:  
            case PAdES_A: 
            case PAdES_C:     
            case PAdES_EPES: 
            case PAdES_X_1:     
            case PAdES_X_2:
            case PAdES_X_L:
                
                signProvider.init("NONE", getProperty(EncryptionAlgName.getLiteral()), 
                                getSignHandler(), getProperty(SecurityProvider.getLiteral()));                 
                break;
                
            default:
                signProvider.init(getProperty(DigestAlgName.getLiteral()), getProperty(EncryptionAlgName.getLiteral()), 
                                getSignHandler(), getProperty(SecurityProvider.getLiteral()));                
                break;
        }

        // get certificate selected
        X509Certificate x509Cert = signProvider.getX509Certificate();
        
        // verify certificate
        x509Cert.checkValidity();
        
        // build and validate chain
        certificateChain = buildAndValidateChain (x509Cert);
        
        // check if verify CRL
        if (Boolean.valueOf(getProperty(VerifyCRL.getLiteral()))) {
            CRLVerifier.verifyCertificateCRLs(x509Cert);
        }

        // set initialized is made
        initialized = true;
        
        return x509Cert;        
    }   
    
    @Override
    public void destroy () throws Exception {
        signProvider.destroy();
        initialized = false;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }
}
