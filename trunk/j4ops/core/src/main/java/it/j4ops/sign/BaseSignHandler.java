/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign;

import it.j4ops.token.TokenInfo;
import it.j4ops.sign.provider.KeyIDAndX509Cert;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

/**
 *
 * @author fzanutto
 */
public class BaseSignHandler implements SignHandler {
    private Logger logger = Logger.getLogger(this.getClass()); 
    private String pin;
    
    public BaseSignHandler (String pin) {
        this.pin = pin;
    }
    
    @Override
    public String getPassword() throws Exception {
        return pin;
    }    

    @Override
    public KeyIDAndX509Cert selectKeyIDAndX509Cert(List<KeyIDAndX509Cert> lstKeyAndX509Cert) throws Exception {
        logger.debug("lstKeyAndX509Cert.size:" + lstKeyAndX509Cert.size());
        
        for (KeyIDAndX509Cert keyIDAndX509Cert : lstKeyAndX509Cert) {
            X509Certificate x509Cert =  keyIDAndX509Cert.getX509Cert();
            boolean []keyUsage = x509Cert.getKeyUsage();
            // 1 nonRepudiation
            if (keyUsage != null && keyUsage[1] == true) {
                logger.debug("select certificate sn:" + x509Cert.getSerialNumber());
                return keyIDAndX509Cert;
            }
        }
        
        logger.debug("no certificate selected");
        
        return null;
    }
    
    @Override
    public TokenInfo selectToken(List<TokenInfo> lstTokens) throws Exception {
        if (lstTokens.size() > 0) {
            return lstTokens.get(0);
        }
        return null;
    }    
    
    @Override
    public SignerInformation selectSigner (Store certs, SignerInformationStore signers)  throws Exception {
        Iterator iterSigns = signers.getSigners().iterator();
        SignerInformation selectSigner = null;
        if (iterSigns.hasNext()) {
            selectSigner = (SignerInformation)iterSigns.next();
            if (selectSigner.getCounterSignatures() != null && selectSigner.getCounterSignatures().size() > 0) { 
                selectSigner = (SignerInformation)selectSigner.getCounterSignatures().getSigners().iterator().next();
            }
        }
        
        return selectSigner;
    }    
}
