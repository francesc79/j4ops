/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign.cms;

import it.j4ops.SignType;
import it.j4ops.util.DERUtil;
import it.j4ops.util.HexString;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author fzanutto
 */
public class ExternalSignerInfoGenerator {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
        
    private AttributeTable unsignedAttrTable = null;
    private AttributeTable signedAttrTable = null;     
    private ASN1Set unsignedAttr = null;      
    private ASN1Set signedAttr = null;  
    private String encryptionAlgOID;
    private String digestAlgOID;    
    private String securityProvider;
    private SignType signType;

    public ExternalSignerInfoGenerator (SignType signType, String digestAlgOID, String encryptionAlgOID, String securityProvider) {
        this.signType = signType;
        this.digestAlgOID = digestAlgOID;
        this.encryptionAlgOID = encryptionAlgOID;
        this.securityProvider = securityProvider;
        unsignedAttrTable = new AttributeTable(new Hashtable());
        signedAttrTable = new AttributeTable(new Hashtable());
    }

    public static String getDigestAlgName(String digestAlgOID) {
        if (CMSSignedDataGenerator.DIGEST_MD5.equals(digestAlgOID)) {
            return "MD5";
        } else if (CMSSignedDataGenerator.DIGEST_SHA1.equals(digestAlgOID)) {
            return "SHA1";
        } else if (CMSSignedDataGenerator.DIGEST_SHA224.equals(digestAlgOID)) {
            return "SHA224";
        } else if (CMSSignedDataGenerator.DIGEST_SHA256.equals(digestAlgOID)) {
            return "SHA256"; 
        } else if (CMSSignedDataGenerator.DIGEST_SHA384.equals(digestAlgOID)) {
            return "SHA384"; 
        } else if (CMSSignedDataGenerator.DIGEST_SHA512.equals(digestAlgOID)) {
            return "SHA512";             
        } else {
            return digestAlgOID;
        }
    } 
    
    public static String getOIDFromDigestAlgName (String digestName) {
        if ("MD5".equals(digestName)) {
            return CMSSignedDataGenerator.DIGEST_MD5;
        }
        else if ("SHA1".equals(digestName)) {
            return CMSSignedDataGenerator.DIGEST_SHA1;
        }  
        else if ("SHA224".equals(digestName)) {
            return CMSSignedDataGenerator.DIGEST_SHA224;
        } 
        else if ("SHA256".equals(digestName)) {
            return CMSSignedDataGenerator.DIGEST_SHA256;
        }  
        else if ("SHA384".equals(digestName)) {
            return CMSSignedDataGenerator.DIGEST_SHA384;
        }
        else if ("SHA512".equals(digestName)) {
            return CMSSignedDataGenerator.DIGEST_SHA512;
        }         
        else {
            return digestName;
        }        
    } 
    
    
    public String getEncryptionAlgName() {
        if (CMSSignedDataGenerator.ENCRYPTION_DSA.equals(encryptionAlgOID)) {
            return "DSA";
        } else if (CMSSignedDataGenerator.ENCRYPTION_RSA.equals(encryptionAlgOID)) {
            return "RSA";
        } else {
            return encryptionAlgOID;
        }
    }  
    
    public static String getOIDFromEncryptionAlgName(String encryptionAlgName) {
        if ("DSA".equals(encryptionAlgName)) {
            return CMSSignedDataGenerator.ENCRYPTION_DSA;
        }
        else if ("RSA".equals(encryptionAlgName)) {
            return CMSSignedDataGenerator.ENCRYPTION_RSA;
        }
        else {
            return encryptionAlgName;
        }
    }       
    
    public byte[] getPdfBytesToSign(byte[] hash, Date signingTime, 
                                    DERObjectIdentifier contentType, 
                                    X509Certificate x509Cert,
                                    TimeStampToken timeStampToken) throws IOException,
                                    SignatureException, InvalidKeyException, NoSuchProviderException,
                                    NoSuchAlgorithmException, CertificateEncodingException,
                                    CMSException {

        // build signed attributes
        ASN1EncodableVector signedAttrVector = buildSignedAttributes (hash, signingTime, contentType, x509Cert);       
        
        // build unsigned attributes
        ASN1EncodableVector unsignedAttrVector = buildUnsignedAttributes (hash, timeStampToken); 
        
        // calculate hash
        hash = DERUtil.getHash (DERUtil.toByteArray(new DERSet(signedAttrVector)), digestAlgOID, securityProvider);      

        logger.debug("HASH:" + HexString.hexify(hash));        
        
        ASN1EncodableVector signData = new ASN1EncodableVector(); 
        ASN1EncodableVector algos = new ASN1EncodableVector();
        algos.add(new DERObjectIdentifier(digestAlgOID));
        algos.add(new DERNull());
        signData.add(new DERSequence(algos));
        signData.add(new DEROctetString(hash));        

        return DERUtil.toByteArray(new DERSequence(signData));
    }     
    
    public byte[] getP7xBytesToSign(byte[] hash, Date signingTime, 
                                    DERObjectIdentifier contentType, 
                                    X509Certificate x509Cert,
                                    TimeStampToken timeStampToken) throws IOException,
                                    SignatureException, InvalidKeyException, NoSuchProviderException,
                                    NoSuchAlgorithmException, CertificateEncodingException,
                                    CMSException { 
        
        // build signed attributes
        ASN1EncodableVector signedAttrVector = buildSignedAttributes (hash, signingTime, contentType, x509Cert);       
        
        // build unsigned attributes
        ASN1EncodableVector unsignedAttrVector = buildUnsignedAttributes (hash, timeStampToken);             
            
        return DERUtil.toByteArray(new DERSet(signedAttrVector));
    }   

    protected ASN1EncodableVector buildUnsignedAttributes (byte[] hash, TimeStampToken timeStampToken) throws IOException  {
        ASN1EncodableVector unsignedAttrVector = new ASN1EncodableVector();        

        Hashtable attrMap = unsignedAttrTable.toHashtable(); 
        
        // check if add id_aa_timeStampToken attribute
        if (timeStampToken != null) {        
            if (attrMap.containsKey (PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) {
                unsignedAttrVector.add ((Attribute)attrMap.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken));
                attrMap.remove (PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            }
            else { 
                ASN1InputStream tempstream = new ASN1InputStream(new ByteArrayInputStream(timeStampToken.getEncoded()));

                // time Stamp token : id-aa-timeStampToken da RFC3161, alias old
                // id-smime-aa-timeStampToken
                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add (new DERObjectIdentifier(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId()));

                ASN1Sequence seq = (ASN1Sequence) tempstream.readObject();
                v.add(new DERSet((DERObject) seq.getObjectAt(1)));
                unsignedAttrVector.add(new DERSequence(v));                
            }   
        }
        
        // add other attributes
        Iterator it = attrMap.values().iterator();
        while (it.hasNext()) {
            unsignedAttrVector.add(Attribute.getInstance(it.next()));
        }         
        
        unsignedAttr = new DERSet(unsignedAttrVector);
        
        return unsignedAttrVector;    
    }
    
    
    protected ASN1EncodableVector buildSignedAttributes(byte[] hash, Date signingTime, 
                                                      DERObjectIdentifier contentType, X509Certificate x509Cert)
                                                      throws NoSuchAlgorithmException, NoSuchProviderException, 
                                                      CertificateEncodingException, IOException, CMSException {        
        ASN1EncodableVector signedAttrVector = new ASN1EncodableVector();

        Hashtable attrMap = signedAttrTable.toHashtable();
        if (contentType != null) {
            if (attrMap.containsKey (CMSAttributes.contentType)) {
                signedAttrVector.add ((Attribute)attrMap.get(CMSAttributes.contentType));
                attrMap.remove (CMSAttributes.contentType);
            }
            else {
                signedAttrVector.add (new Attribute(CMSAttributes.contentType, new DERSet (contentType)));
            }
        }
        if (attrMap.containsKey (CMSAttributes.signingTime)) {
            signedAttrVector.add ((Attribute)attrMap.get(CMSAttributes.signingTime));
            attrMap.remove (CMSAttributes.signingTime);
        }
        else {        
            signedAttrVector.add (new Attribute (CMSAttributes.signingTime, new DERSet(new Time (signingTime))));            
        }
        if (attrMap.containsKey (CMSAttributes.messageDigest)) {
            signedAttrVector.add ((Attribute)attrMap.get (CMSAttributes.messageDigest));
            attrMap.remove (CMSAttributes.messageDigest);
        }
        else {         
            signedAttrVector.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hash))));     
        }
                
        // check if add id_aa_signingCertificateV2 attribute
        if (signType != SignType.Pkcs7 && signType != SignType.PDF && signType != SignType.XMLDSIG) {
            if (attrMap.containsKey (PKCSObjectIdentifiers.id_aa_signingCertificateV2)) {
                signedAttrVector.add ((Attribute)attrMap.get (PKCSObjectIdentifiers.id_aa_signingCertificateV2));
                attrMap.remove (PKCSObjectIdentifiers.id_aa_signingCertificateV2);
            }
            else {          
                if (x509Cert != null) {
                    signedAttrVector.add(buildSigningCertificateV2Attribute(x509Cert));
                }
            }
        }
        
        // add other attributes
        Iterator it = attrMap.values().iterator();
        while (it.hasNext()) {
            signedAttrVector.add(Attribute.getInstance(it.next()));
        }        

        signedAttr = new DERSet(signedAttrVector);
                
        return signedAttrVector;
    }    
    
    protected Attribute buildSigningCertificateV2Attribute (X509Certificate x509Cert) 
                                                         throws NoSuchAlgorithmException, NoSuchProviderException, 
                                                         CertificateEncodingException, IOException, CMSException {

        byte[] certHash = DERUtil.getHash(x509Cert.getEncoded(), digestAlgOID, securityProvider);

        X509CertificateHolder holder = new X509CertificateHolder(x509Cert.getEncoded());
        X500Name x500name = holder.getIssuer();

        GeneralName generalName = new GeneralName(x500name);
        GeneralNames generalNames = new GeneralNames(generalName);
        DERInteger serialNum = new DERInteger(holder.getSerialNumber());
        
        IssuerSerial issuerserial = new IssuerSerial(generalNames, serialNum);
        ESSCertIDv2 essCert = new ESSCertIDv2(new AlgorithmIdentifier(digestAlgOID), certHash, issuerserial);

        SigningCertificateV2 scv2 = new SigningCertificateV2(new ESSCertIDv2[] {essCert});        
        
        return new Attribute (PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(scv2));
    }    
    
    
    public void addTimeStampToken (TimeStampToken timeStampToken) throws IOException {
             
        ASN1InputStream tempstream = new ASN1InputStream(new ByteArrayInputStream(timeStampToken.getEncoded()));

        // time Stamp token : id-aa-timeStampToken da RFC3161, alias old
        // id-smime-aa-timeStampToken

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add (new DERObjectIdentifier(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId())); // id-aa-timeStampToken
        ASN1Sequence seq = (ASN1Sequence) tempstream.readObject();
        v.add(new DERSet((DERObject) seq.getObjectAt(1)));
        unsignedAttrTable = unsignedAttrTable.add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSequence (v));                        
    }
    
    
    /**
     * @return the unsignedAttrTable
     */
    public AttributeTable getUnsignedAttrTable() {
        return unsignedAttrTable;
    }

    /**
     * @return the signedAttrTable
     */
    public AttributeTable getSignedAttrTable() {
        return signedAttrTable;
    }
    
    public SignerInfoGenerator generate (final byte [] hash, final byte []signedBytes, X509Certificate x509Cert) throws CertificateEncodingException, OperatorCreationException, IOException {

        X509CertificateHolder holder = new X509CertificateHolder(x509Cert.getEncoded());
        IssuerAndSerialNumber encSid = new IssuerAndSerialNumber(holder.getIssuer(), x509Cert.getSerialNumber());        
        
        ContentSigner contentSigner = new ContentSigner() {
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                AlgorithmIdentifier encAlgId = null;
                if (encryptionAlgOID.equals(CMSSignedDataGenerator.ENCRYPTION_DSA)) {
                    encAlgId = new AlgorithmIdentifier(new DERObjectIdentifier(encryptionAlgOID));
                } else {
                    encAlgId = new AlgorithmIdentifier(new DERObjectIdentifier(encryptionAlgOID), new DERNull());
                }             
                return encAlgId;
            }

            @Override
            public OutputStream getOutputStream() {
                return new ByteArrayOutputStream();
            }

            @Override
            public byte[] getSignature() {                
                return signedBytes;
            }
        };   
        DigestCalculatorProvider digestCalculator = new DigestCalculatorProvider(){

            @Override
            public DigestCalculator get(AlgorithmIdentifier ai) throws OperatorCreationException {
                return new DigestCalculator () {

                    @Override
                    public AlgorithmIdentifier getAlgorithmIdentifier() {
                        return new AlgorithmIdentifier(new DERObjectIdentifier(digestAlgOID), new DERNull());
                    }

                    @Override
                    public OutputStream getOutputStream() {
                        return null;
                    }

                    @Override
                    public byte[] getDigest() {
                        return hash;
                    }
                };
            }
        
        };

        return new SignerInfoGenerator(new SignerIdentifier (encSid),
                                       contentSigner,
                                       digestCalculator,
                                       new DefaultSignedAttributeTableGenerator (new AttributeTable(signedAttr)),
                                       new SimpleAttributeTableGenerator (new AttributeTable(unsignedAttr)));
    }
    

}
