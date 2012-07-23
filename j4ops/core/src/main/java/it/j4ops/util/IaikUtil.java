/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.util;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import it.j4ops.sign.provider.KeyIDAndX509Cert;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.apache.log4j.Logger;

/**
 *
 * @author fzanutto
 */
public class IaikUtil {
    private static Logger logger = Logger.getLogger(IaikUtil.class);

    public static Token selectToken(Module pkcs11Module, int slotID)
        throws TokenException, IOException {
        
        assert null != pkcs11Module : "module not valid";
        
        logger.info ("getting list of all tokens");
        Slot[] slotsWithToken = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);
        if (slotsWithToken == null || slotID > slotsWithToken.length) {
            throw new TokenException ("Slot index error");
        }
        Token token = slotsWithToken[slotID].getToken();
        TokenInfo tokenInfo = token.getTokenInfo();
        long tokenID = token.getTokenID();
        logger.info("Token ID: " + tokenID);
        logger.info(tokenInfo);        
        
        return token;
    }    
    
    public static Token selectToken(Module pkcs11Module)
        throws TokenException, IOException {

        assert null != pkcs11Module : "module not valid";
        
        logger.info ("getting list of all tokens");
        Slot[] slotsWithToken = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        Token[] tokens = new Token[slotsWithToken.length];
        HashMap tokenIDtoToken = new HashMap(tokens.length);

        for (int i = 0; i < slotsWithToken.length; i++) {
            tokens[i] = slotsWithToken[i].getToken();
            TokenInfo tokenInfo = tokens[i].getTokenInfo();
            long tokenID = tokens[i].getTokenID();
            tokenIDtoToken.put(new Long(tokenID), tokens[i]);
            logger.info("Token ID: " + tokenID);
            logger.info(tokenInfo);
        }
        Token token = null;
        Long selectedTokenID = null;
        if (tokens.length == 0) {
            logger.info("There is no slot with a present token.");
        } else {
            selectedTokenID = new Long(tokens[0].getTokenID());
            token = tokens[0];
        }
        return token;
    }

    public static Session openAuthorizedSession(Token token, boolean rwSession, String PIN)
        throws TokenException, IOException {
        
        assert null != token : "token not valid";        
        
        logger.info("opening session");
        Session session = token.openSession (Token.SessionType.SERIAL_SESSION, rwSession, null, null);
        TokenInfo tokenInfo = token.getTokenInfo();
        if (tokenInfo.isLoginRequired()) {
            if (tokenInfo.isProtectedAuthenticationPath()) {
                logger.info("Please enter the user-PIN at the PIN-pad of your reader.");
                session.login (Session.UserType.USER, null); // the token prompts the PIN by other means; e.g. PIN-pad
            } else {
                session.login (Session.UserType.USER, PIN.toCharArray());
            }
        }

        return session;
    }
    
    public static PrivateKey getPrivateKey (Session session, PrivateKey keyTemplate, byte []keyID) throws TokenException {
        PrivateKey key = null;
        
        // find key with keyID     
        keyTemplate.getId().setByteArrayValue(keyID);
        
        session.findObjectsInit(keyTemplate);
        Object[] matchingKeys;
        if ((matchingKeys = session.findObjects(1)).length > 0) {
            key = (PrivateKey)matchingKeys[0]; 
        }
        session.findObjectsFinal();        
        
        return key;
    }

    public static List<KeyIDAndX509Cert> getCertificates (Session session, String provider) throws TokenException, IOException, CertificateException, NoSuchProviderException {
        ArrayList<KeyIDAndX509Cert> lstKeyIDAndX509Cert = new ArrayList<KeyIDAndX509Cert>(4);
        
        assert null != session : "session not valid";                
        
        // get certificates
        X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
        session.findObjectsInit(certificateTemplate);
        Object[] correspondingCertificates;
        while ((correspondingCertificates = session.findObjects(1)).length > 0) {
            X509PublicKeyCertificate cert = (X509PublicKeyCertificate)correspondingCertificates[0];
            
            KeyIDAndX509Cert keyIDAndX509Cert = new KeyIDAndX509Cert();
            keyIDAndX509Cert.setX509Cert (X509Util.toX509Certificate(cert.getValue().getByteArrayValue(), provider));
            keyIDAndX509Cert.setCertLabel(new String(cert.getLabel().getCharArrayValue()));
            keyIDAndX509Cert.setKeyID(cert.getId().getByteArrayValue());
            lstKeyIDAndX509Cert.add(keyIDAndX509Cert);
        }
        session.findObjectsFinal(); 

        return lstKeyIDAndX509Cert;
    }    
}
