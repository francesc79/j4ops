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
        Session session =
            token.openSession(Token.SessionType.SERIAL_SESSION, rwSession, null, null);

        TokenInfo tokenInfo = token.getTokenInfo();
        if (tokenInfo.isLoginRequired()) {
            if (tokenInfo.isProtectedAuthenticationPath()) {
                logger.info("Please enter the user-PIN at the PIN-pad of your reader.");
                session.login(Session.UserType.USER, null); // the token prompts the PIN by other means; e.g. PIN-pad
            } else {
                session.login(Session.UserType.USER, PIN.toCharArray());
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
    
/*
    public static KeyAndCertificate selectKeyAndCertificate(Session session, Key keyTemplate, String key_label)
        throws TokenException, IOException {
        if (session == null) {
            throw new NullPointerException("Argument \"session\" must not be null.");
        }
        if (keyTemplate == null) {
            throw new NullPointerException("Argument \"keyTemplate\" must not be null.");
        }

        logger.info("searching for keys");

        ArrayList keyList = new ArrayList(4);

        session.findObjectsInit(keyTemplate);
        Object[] matchingKeys;

        while ((matchingKeys = session.findObjects(1)).length > 0) {
            keyList.add(matchingKeys[0]);
        }
        session.findObjectsFinal();

        // try to find the corresponding certificates for the signature keys
        HashMap keyToCertificateTable = new HashMap(4);
        Iterator keyListIterator = keyList.iterator();
        while (keyListIterator.hasNext()) {
            PrivateKey signatureKey = (PrivateKey) keyListIterator.next();
            
            byte[] keyID = signatureKey.getId().getByteArrayValue();
            X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
            certificateTemplate.getId().setByteArrayValue(keyID);

            session.findObjectsInit(certificateTemplate);
            Object[] correspondingCertificates = session.findObjects(1);

            if (correspondingCertificates.length > 0) {
                keyToCertificateTable.put(signatureKey, correspondingCertificates[0]);
            }
            session.findObjectsFinal();
        }

        Key selectedKey = null;
        X509PublicKeyCertificate correspondingCertificate = null;
        if (keyList.isEmpty()) {
            logger.info("Found NO matching key that can be used.");
        } else if (keyList.size() == 1) {
            // there is no choice, take this key
            selectedKey = (Key) keyList.get(0);
            // create a IAIK JCE certificate from the PKCS11 certificate
            correspondingCertificate = (X509PublicKeyCertificate) keyToCertificateTable.get(selectedKey);
            String correspondingCertificateString = X509Util.toString(correspondingCertificate);
            logger.info("Found just one private RSA signing key. This key will be used:");
            logger.info(selectedKey);
            logger.info("--------------------------------------------------------------------------------");
            logger.info("The certificate for this key is:");
            logger.info((correspondingCertificateString != null)
                ? correspondingCertificateString
                : "<no certificate found>");
        } else {
            // give the user the choice
            logger.info("found these private RSA signing keys:");
            HashMap objectHandleToObjectMap = new HashMap(keyList.size());
            Iterator keyListIterator2 = keyList.iterator();

            while (keyListIterator2.hasNext()) {
                Object signatureKey = (Object) keyListIterator2.next();

                long objectHandle = signatureKey.getObjectHandle();
                objectHandleToObjectMap.put(new Long(objectHandle), signatureKey);
                correspondingCertificate = (X509PublicKeyCertificate) keyToCertificateTable.get(signatureKey);
                String correspondingCertificateString = X509Util.toString(correspondingCertificate);
                logger.info("________________________________________________________________________________");
                logger.info("RSA signature key with handle: " + objectHandle);
                logger.info(signatureKey);
                logger.info("--------------------------------------------------------------------------------");
                logger.info("The certificate for this key is: ");
                logger.info((correspondingCertificateString != null) ? correspondingCertificateString : "<no certificate found>");
                logger.info("________________________________________________________________________________");

                if (signatureKey instanceof RSAPrivateKey) {
                    RSAPrivateKey key = (RSAPrivateKey) signatureKey;

                    if (key_label != null && key_label.equals(key.getLabel().toString())) {

                        selectedKey = key;
                        correspondingCertificate = (X509PublicKeyCertificate) keyToCertificateTable.get(selectedKey);
                        break;
                    }
                }
            }

//      boolean gotObjectHandle = false;
//      Long selectedObjectHandle;
//      while (!gotObjectHandle) {
//          
//        
//      	BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
//      	String objectHandleString = input.readLine();
//        
//        try {
//          selectedObjectHandle = new Long(objectHandleString);
//          selectedKey = (RSAPrivateKey) objectHandleToObjectMap.get(selectedObjectHandle);
//          if (selectedKey != null) {
//            correspondingCertificate = (X509PublicKeyCertificate) keyToCertificateTable.get(selectedKey);
//            gotObjectHandle = true;
//          } else {
//            output.println("An object with the handle \"" + objectHandleString + "\" does not exist. Try again.");
//          }
//        } catch (NumberFormatException ex) {
//          output.println("The entered handle \"" + objectHandleString + "\" is invalid. Try again.");
//        }
//      }
        }

        return (selectedKey != null)
            ? new KeyAndCertificate(selectedKey, correspondingCertificate)
            : null;
    }
*/

 
}
