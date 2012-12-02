/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign.cms;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

/**
 *
 * @author fzanutto
 */
public class ExternalCMSSignedDataGenerator extends CMSSignedDataGenerator {
    private static Logger logger = LoggerFactory.getLogger(ExternalCMSSignedDataGenerator.class);
    private CMSTypedData content = null;
    
    private ExternalCMSSignedDataGenerator () {
    }
    
    public ExternalCMSSignedDataGenerator (byte []contentBytes, String securityProvider) throws Exception {
        try {
            assert null != contentBytes : "not valid content bytes";
            assert null != securityProvider : "not valid provider";
            
            logger.debug(String.format("parsing %d bytes", contentBytes.length));
            
            CMSSignedData origSignedData = new CMSSignedData(contentBytes);
            content = (CMSTypedData)origSignedData.getSignedContent();
            
            Store storeAttrCerts = origSignedData.getAttributeCertificates();
            logger.debug(String.format("found %d storeAttrCerts", storeAttrCerts.getMatches(null).size()));
            addAttributeCertificates(storeAttrCerts);
            
            SignerInformationStore signers = origSignedData.getSignerInfos();
            logger.debug(String.format("found %d signers", signers.size()));
            addSigners(signers);

            Store storeCerts = origSignedData.getCertificates();
            logger.debug(String.format("found %d storeCerts", storeCerts.getMatches(null).size()));
            addCertificates(storeCerts);           
            
            Store storeCRLs = origSignedData.getCRLs(); 
            logger.debug(String.format("found %d storeCRLs", storeCRLs.getMatches(null).size()));
            addCRLs(storeCRLs);
        }
        catch (CMSException ex) {
            //logger.error (ex.getMessage(), ex);
            content = new CMSProcessableByteArray(contentBytes);          
        }
    }
    
    public ExternalCMSSignedDataGenerator (CMSTypedData content) {
        this.content = content;
    }            
 
    public CMSSignedData generate (boolean attachedSignature) throws CMSException {
        return generate(content, attachedSignature);
    } 
        
    public CMSTypedData getContent() {
        return content;
    } 
    
    public SignerInformationStore getSignerInfos () {
        return new SignerInformationStore(_signers);
    }
    
    public Store getCertificates() throws IOException {
        ArrayList<X509CertificateHolder> lstCerts = new ArrayList<X509CertificateHolder> ();
        for (Object cert : certs) {
            lstCerts.add(new X509CertificateHolder(((X509CertificateStructure) cert).getEncoded()));
        }
        return new CollectionStore(lstCerts);
    }
    
    public Store getCRLs() throws IOException {
        ArrayList<X509CertificateHolder> lstCRLs = new ArrayList<X509CertificateHolder> ();
        for (Object crl : crls) {
            lstCRLs.add(new X509CertificateHolder(((X509CertificateStructure) crl).getEncoded()));
        }
        return new CollectionStore(lstCRLs);        
    }    
    
    public static SignerInformation addCounterSigners (SignerInformation signerInformation, 
                                                       SignerInfoGenerator signerInfoGenerator) throws Exception  {
        ExternalCMSSignedDataGenerator externalCMSSignedDataGenerator = 
            new ExternalCMSSignedDataGenerator ();     
        externalCMSSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
        return SignerInformation.addCounterSigners(signerInformation, 
            externalCMSSignedDataGenerator.generateCounterSigners(signerInformation));  
    }
    
    private SignerInfo replaceCounterSignerInfo (SignerInfo signerInfo, Attribute attrHash, SignerInfo newSignerInfo) {
        
        DERObject hashObject = attrHash.getAttrValues().getObjectAt(0).getDERObject();
        byte []hash = ((ASN1OctetString)hashObject).getOctets();
        
        ASN1EncodableVector allCSAttrs = new AttributeTable (signerInfo.getUnauthenticatedAttributes()).getAll(CMSAttributes.counterSignature);
        for (int i = 0; i < allCSAttrs.size(); i ++) {
            Attribute counterSignatureAttribute = (Attribute)allCSAttrs.get(i);
            ASN1Set values = counterSignatureAttribute.getAttrValues();
            for (Enumeration en = values.getObjects(); en.hasMoreElements();) {                    
                SignerInfo si = SignerInfo.getInstance(en.nextElement());
                AttributeTable attrSign = new AttributeTable (si.getAuthenticatedAttributes());
                //AttributeTable attrUnsign = new AttributeTable (si.getUnauthenticatedAttributes());                        
                if (attrSign.get(CMSAttributes.messageDigest).equals(attrHash)) {                        
                        ASN1EncodableVector newallCSAttrs = new ASN1EncodableVector ();
                        for (int j = 0; j < allCSAttrs.size(); j ++) {
                            Attribute a = (Attribute)allCSAttrs.get(i);
                            if (!a.equals(counterSignatureAttribute)) {
                                newallCSAttrs.add(a);
                            }
                        }
                        newallCSAttrs.add(new Attribute(CMSAttributes.counterSignature, new DERSet(newSignerInfo.toASN1Object())));
                        
                        return new SignerInfo(signerInfo.getSID(), signerInfo.getDigestAlgorithm(), 
                                              signerInfo.getAuthenticatedAttributes(), signerInfo.getDigestEncryptionAlgorithm(),
                                              signerInfo.getEncryptedDigest(), new DERSet(new AttributeTable (newallCSAttrs).toASN1EncodableVector()));                        
                }
                else {  
                    SignerInfo siTmp = null;
                    if ((siTmp = replaceCounterSignerInfo(si, attrHash, newSignerInfo)) != null) {
                        return new SignerInfo(si.getSID(), si.getDigestAlgorithm(), 
                                              si.getAuthenticatedAttributes(), si.getDigestEncryptionAlgorithm(),
                                              si.getEncryptedDigest(), siTmp.getUnauthenticatedAttributes()); 
                    }                    
                }                        
            }
        }      
        return null;
    }
    
    private boolean match (SignerInformation siA, SignerInformation siB) {        
        Attribute stSiA = siA.getSignedAttributes().get(CMSAttributes.signingTime);
        Attribute stSiB = siB.getSignedAttributes().get(CMSAttributes.signingTime);
        Attribute mdSiA = siA.getSignedAttributes().get(CMSAttributes.messageDigest);
        Attribute mdSiB = siB.getSignedAttributes().get(CMSAttributes.messageDigest);
        return  mdSiA.equals(mdSiB) && stSiA.equals(stSiB) && siA.getSID().equals(siB.getSID());
    }
    
    
    public void addCounterSigner (SignerInformation signerInformation, 
                                  SignerInfoGenerator signerInfoGenerator) throws Exception  {
        
        // generate counter sign
        ExternalCMSSignedDataGenerator externalCMSSignedDataGenerator = 
            new ExternalCMSSignedDataGenerator ();     
        externalCMSSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
        SignerInformation newSignerInformation = SignerInformation.addCounterSigners(signerInformation, 
                                externalCMSSignedDataGenerator.generateCounterSigners(signerInformation));  
        
        // replace the signer
        if (signerInformation.isCounterSignature()) {
            Attribute attrHash = signerInformation.getSignedAttributes().get(CMSAttributes.messageDigest);
            for (int index = 0; index < _signers.size(); index ++) {
                SignerInformation si = (SignerInformation)_signers.get(index);                

                SignerInfo signerInfo = replaceCounterSignerInfo (si.toASN1Structure(), attrHash, newSignerInformation.toASN1Structure());
                if (signerInfo != null) {
                    si = SignerInformation.replaceUnsignedAttributes(si, new AttributeTable(signerInfo.getUnauthenticatedAttributes()));
                    _signers.set(index, si);
                }                
            }
        }
        else {
            for (int index = 0; index < _signers.size(); index ++) {
                SignerInformation si = (SignerInformation)_signers.get(index);

                //if (si.getSID().equals(signerInformation.getSID())) {
                if (match(signerInformation, si)) {
                    _signers.set(index, newSignerInformation);
                }
            }
        }        
    }    
    
    public static int printSigns (int level, Store certs, SignerInformationStore selectSignerStore) {
        int count = 0, tot = 0;
        level ++;
        Iterator iterSigns = selectSignerStore.getSigners().iterator();
        while (iterSigns.hasNext()) {
            logger.debug (String.format("---------------------------------- LEVEL (%d) ----------------------------------------", level));
            
            SignerInformation selectSigner = (SignerInformation)iterSigns.next();
            SignerId sid = selectSigner.getSID();
            
            Attribute attr = selectSigner.getSignedAttributes().get(CMSAttributes.signingTime);
            logger.debug (String.format("DateSign:%s", attr.getAttrValues().toString()));
            
            Collection lstCerts = certs.getMatches(sid);
            
            logger.debug (String.format("-------------  CERT (%d) ------------", lstCerts.size()));
            
            Iterator iterCerts = lstCerts.iterator();
            while (iterCerts.hasNext()) {
                X509CertificateHolder cert = (X509CertificateHolder)iterCerts.next();
                logger.debug (String.format("SerialNumber:%s", cert.getSerialNumber()));
                logger.debug (String.format("Issuer:%s", cert.getIssuer()));            
                logger.debug (String.format("Subject:%s", cert.getSubject()));
            }
            count ++;
            tot ++;
            
            // get child signs
            if (selectSigner.getCounterSignatures().size() > 0) {
                tot += printSigns (level, certs, selectSigner.getCounterSignatures());
            }
        }
        logger.debug (String.format("---------------------------------- LEVEL (%d) COUNT (%d) ----------------------------------------", level, count));
        if (level == 1) {
            logger.debug (String.format("---------------------------------- LEVEL (%d) TOT COUNT (%d) ----------------------------------------", level, tot));
        }
        
        return tot;
    }    
}
