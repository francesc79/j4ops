/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.gui;

import it.j4ops.SignType;
import it.j4ops.gui.dialog.CertificateDialog;
import it.j4ops.gui.dialog.PinDiaolog;
import it.j4ops.gui.dialog.SignerDialog;
import it.j4ops.gui.dialog.TokenDialog;
import it.j4ops.sign.SignHandler;
import it.j4ops.sign.provider.KeyIDAndX509Cert;
import it.j4ops.token.TokenInfo;
import it.j4ops.util.DNParser;
import it.j4ops.verify.bean.SignerInfo;
import java.awt.Dialog;
import java.awt.Frame;
import java.awt.Window;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

/**
 *
 * @author zanutto
 */
public class GuiSignHandler implements SignHandler {
    private Window owner = null;
    
    public GuiSignHandler (Window owner) {
        this.owner = owner;
    }
    
    protected SignerInfo checkSignature (Store certs, SignerInformation signer, int level) throws Exception {
        SignerId signerId = signer.getSID();
        SignerInfo signerInfo = null;

        Collection certCollection = certs.getMatches(signerId);
        Iterator certIter = certCollection.iterator();
        while (certIter.hasNext()) {
            X509CertificateHolder certHolder = (X509CertificateHolder) certIter.next();

            Attribute attrSigningTime = signer.getSignedAttributes().get(CMSAttributes.signingTime);
            Enumeration enumer = attrSigningTime.getAttrValues().getObjects();
            ASN1UTCTime dateSign = (ASN1UTCTime)enumer.nextElement();                

            // create signer informations
            signerInfo = new SignerInfo ();
            signerInfo.setAuthor(DNParser.parse(certHolder.getSubject().toString(), "CN"));
            signerInfo.setDateSign(dateSign.getDate());
            signerInfo.setCounterSignature(signer.isCounterSignature());
            signerInfo.setSignerInformation(signer);
            signerInfo.setLevel(level);

            // check signed type
            if (signer.getSignedAttributes() != null && signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) != null) {
                signerInfo.setSignType(SignType.CAdES_BES); 
                if (signer.getUnsignedAttributes() != null && signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null) {
                    signerInfo.setSignType(SignType.CAdES_T);                        
                    if (signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs) != null &&
                        signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs) != null) {
                        signerInfo.setSignType(SignType.CAdES_C);
                    }
                }                    
            }
            else {
                signerInfo.setSignType(SignType.Pkcs7);
            }                

            // get certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509"); 
            InputStream is = null;
            try {
                is = new ByteArrayInputStream(certHolder.toASN1Structure().getEncoded());
                signerInfo.setX509Cert((X509Certificate) cf.generateCertificate(is));
            } 
            finally {
                try {
                    if (is != null) {
                        is.close(); 
                        is = null;
                    }
                }
                catch (Exception ex) {}
            }                   
        } 
        return signerInfo;
    }
    
    protected void checkCounterSignatures (ArrayList<SignerInfo> lstSigners, int level, Store certs, SignerInformationStore counterSignatures) throws Exception {
        Collection lstCounterSigners = counterSignatures.getSigners();
        Iterator iter = lstCounterSigners.iterator();  
        level ++;
        while (iter.hasNext()) {
            SignerInformation signer = (SignerInformation) iter.next();
            SignerInfo si = checkSignature (certs, signer, level);
            lstSigners.add(si);            
            checkCounterSignatures (lstSigners, level, certs, signer.getCounterSignatures());
        }
    }    
    
    
    @Override
    public SignerInformation selectSigner (Store certs, SignerInformationStore signers)  throws Exception  {
        ArrayList<SignerInfo> lstSigners = new ArrayList<SignerInfo>();
        Iterator iter = signers.getSigners().iterator();
        int level = 0;
        while(iter.hasNext()) {
            SignerInformation si = (SignerInformation)iter.next();            
            SignerInfo signerInfo = checkSignature (certs, si, level);
            lstSigners.add(signerInfo);
            checkCounterSignatures(lstSigners, level, certs, si.getCounterSignatures());
        }
        SignerDialog signerDialog = new SignerDialog (owner, Dialog.ModalityType.APPLICATION_MODAL, lstSigners);
        signerDialog.setVisible(true);
        if (signerDialog.getSelectedSignerInfo() == null) {
            throw new Exception ("user cancel");
        }
        return signerDialog.getSelectedSignerInfo().getSignerInformation();        
    }

    @Override
    public String getPassword() throws Exception {
        PinDiaolog pinDialog = new PinDiaolog (owner, Dialog.ModalityType.APPLICATION_MODAL);
        pinDialog.setVisible(true);
        String pin = pinDialog.getPin();
        if (pin == null || pin.equals("")) {
            throw new Exception ("user cancel");
        }       
        return pinDialog.getPin();        
    }

    @Override
    public TokenInfo selectToken(List<TokenInfo> lstTokenInfos) throws Exception {
        if (lstTokenInfos.size() == 1) {
            return lstTokenInfos.get(0);
        }
        else {        
            TokenDialog tokenDialog = new TokenDialog (owner, Dialog.ModalityType.APPLICATION_MODAL, lstTokenInfos);
            tokenDialog.setVisible(true);
            TokenInfo tokenInfo = tokenDialog.getTokenSelected();
            if (tokenInfo == null) {
                throw new Exception ("user cancel");            
            }        
            return tokenInfo;
        }
    }

    @Override
    public KeyIDAndX509Cert selectKeyIDAndX509Cert(List<KeyIDAndX509Cert> lstKeyAndX509Cert) throws Exception {
        List<KeyIDAndX509Cert> tmp = new ArrayList<KeyIDAndX509Cert> ();
        for (KeyIDAndX509Cert keyIDAndX509Cert : lstKeyAndX509Cert) {
            X509Certificate x509Cert =  keyIDAndX509Cert.getX509Cert();
            boolean []keyUsage = x509Cert.getKeyUsage();
            // 1 nonRepudiation
            if (keyUsage != null && keyUsage[1] == true) {
                tmp.add(keyIDAndX509Cert);
            }
        }    
        if (tmp.isEmpty()) {
            throw new Exception ("No certificate valid!");            
        }
        else if (tmp.size() == 1) {
            return tmp.get(0);
        }
        else {          
            CertificateDialog certDialog = new CertificateDialog(owner, Dialog.ModalityType.APPLICATION_MODAL, tmp);
            certDialog.setVisible(true);
            KeyIDAndX509Cert cert = certDialog.getX509CertSelected();
            if (cert == null) {
                throw new Exception ("user cancel");            
            }        
            return cert;   
        }
    }
}
