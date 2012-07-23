/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign;


import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import it.j4ops.XmlSignMode;
import it.j4ops.sign.provider.PKCS12Provider;
import it.j4ops.sign.provider.SignProvider;
import it.j4ops.sign.provider.SunPKCS11Provider;
import it.j4ops.util.DERUtil;
import it.j4ops.util.HexString;
import it.j4ops.util.TimeStampTokenUtil;
import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Properties;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.time.DateFormatUtils;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;
import org.apache.xml.security.Init;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;


/**
 *
 * @author fzanutto
 */
public class XmlSign extends BaseSign {
    private Logger logger = Logger.getLogger(this.getClass());     
    
    private static final String XMLDSIGSpecNS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XAdESSpecNS = "http://uri.etsi.org/01903/v1.3.2#";
    private static enum Id {
        Sign,
        Reference,
        SignedProperties,
        SignatureValue
    }     

    public XmlSign (SignProvider signerProvider, SignHandler signHandler, Properties properties) {
        super(signerProvider, signHandler, properties);        
    }  
    
    private Element buildUnsignedProperties (Document doc, SignType signType) {

        Element upElement = null;
        Element uspElement = null;
        if (signType == SignType.XMLDSIG) {
            upElement = doc.createElementNS(XMLDSIGSpecNS, "ds:UnsignedProperties");
            uspElement = doc.createElementNS(XMLDSIGSpecNS, "ds:UnsignedSignatureProperties");
        }   
        else {
            upElement = doc.createElementNS(XAdESSpecNS, "xades:UnsignedProperties");  
            uspElement = doc.createElementNS(XAdESSpecNS, "xades:UnsignedSignatureProperties");
        }
        upElement.appendChild(uspElement);
        
        return upElement;        
    }
    
    private Element buildSigningCertificateV2Attribute (Document doc, SignType signType, 
                                                        String digestAlg, X509Certificate x509Cert) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CMSException, CertificateEncodingException {
        
        // calculate digest
        byte[] certHash = DERUtil.getHash(x509Cert.getEncoded(), getProperty(DigestAlgName.getLiteral()), getProperty(SecurityProvider.getLiteral()));
        
        // add id_aa_signingCertificateV2
        Element scElement = doc.createElementNS(XAdESSpecNS, "xades:SigningCertificate");
        Element certElement = doc.createElementNS(XAdESSpecNS, "xades:Cert");
        scElement.appendChild(certElement);

        Element certDigestElement = doc.createElementNS(XAdESSpecNS, "xades:CertDigest");
        certElement.appendChild(certDigestElement);                                

        Element digestMethodElement = doc.createElementNS(XMLDSIGSpecNS, "ds:DigestMethod");
        certDigestElement.appendChild(digestMethodElement);
        digestMethodElement.setAttribute("Algorithm", digestAlg);               

        Element digestValueElement = doc.createElementNS(XMLDSIGSpecNS, "ds:DigestValue");
        certDigestElement.appendChild(digestValueElement);
        digestValueElement.setTextContent(new String(Base64.encodeBase64(certHash)));                

        Element issuerSerialElement = doc.createElementNS(XAdESSpecNS, "xades:IssuerSerial");
        certElement.appendChild(issuerSerialElement);

        Element issuerElement = doc.createElementNS(XMLDSIGSpecNS, "ds:X509IssuerName");
        issuerSerialElement.appendChild(issuerElement);
        issuerElement.setTextContent(x509Cert.getIssuerDN().toString());

        Element snElement = doc.createElementNS(XMLDSIGSpecNS, "ds:X509SerialNumber");
        issuerSerialElement.appendChild(snElement); 
        snElement.setTextContent(x509Cert.getSerialNumber().toString());
        
        return scElement;
    }    
    
    private Element buildSignedProperties (Document doc, SignType signType, String digestAlg, 
                                           Date signingTime, X509Certificate x509Cert) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CMSException, CertificateEncodingException {
        Element spElement = null;
        Element sspElement = null;
        Element stElement = null;
        if (signType == SignType.XMLDSIG) {
            spElement = doc.createElementNS(XMLDSIGSpecNS, "ds:SignedProperties");
            sspElement = doc.createElementNS(XMLDSIGSpecNS, "ds:SignedSignatureProperties");
            stElement = doc.createElementNS(XMLDSIGSpecNS, "ds:SigningTime");
        }
        else {
            spElement = doc.createElementNS(XAdESSpecNS, "xades:SignedProperties");
            sspElement = doc.createElementNS(XAdESSpecNS, "xades:SignedSignatureProperties");
            stElement = doc.createElementNS(XAdESSpecNS, "xades:SigningTime");
        }   

        String dateString = DateFormatUtils.ISO_DATETIME_TIME_ZONE_FORMAT.format(signingTime);
        stElement.setTextContent(dateString);        
        
        sspElement.appendChild(stElement);
        if (signType != SignType.XMLDSIG) {
            sspElement.appendChild(buildSigningCertificateV2Attribute (doc, signType, digestAlg, x509Cert));
        }
        spElement.appendChild(sspElement);
        
        return spElement;
    }
    
    private Element buildQualifyingProperties (EnumMap<Id, String> mapId, Document doc, SignType signType, 
                                               String digestAlg, Date signingTime, X509Certificate x509Cert) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CMSException, CertificateEncodingException {
        Element qpElement = null;
        if (signType == SignType.XMLDSIG) {
            qpElement = doc.createElementNS(XMLDSIGSpecNS, "ds:QualifyingProperties");
        }
        else {
            qpElement = doc.createElementNS(XAdESSpecNS, "xades:QualifyingProperties");
            qpElement.setAttribute("Target", "#" + mapId.get(Id.Sign));
        }
        
        Element eSignedProperties = buildSignedProperties (doc, signType, digestAlg, signingTime, x509Cert);
        eSignedProperties.setAttribute("Id", mapId.get(Id.SignedProperties));
        eSignedProperties.setIdAttribute("Id", true);
        
        qpElement.appendChild(eSignedProperties);        
        qpElement.appendChild(buildUnsignedProperties (doc, signType));
        
        return qpElement;
    }
    
    private Element buildSignatureTimeStamp (EnumMap<Id, String> mapId, Document doc, SignType signType, TimeStampToken timeStampToken) throws IOException {
        Element stsElement = null;
        Element encapsulatedTimeStampElement = null;
        if (signType == SignType.XMLDSIG) {
            stsElement = doc.createElementNS(XMLDSIGSpecNS, "ds:SignatureTimeStamp");                  
            encapsulatedTimeStampElement = doc.createElementNS(XMLDSIGSpecNS, "ds:EncapsulatedTimeStamp");
            encapsulatedTimeStampElement.setTextContent(Base64.encodeBase64String(timeStampToken.getEncoded()));            
        }   
        else {
            stsElement = doc.createElementNS(XAdESSpecNS, "xades:SignatureTimeStamp");                    
            encapsulatedTimeStampElement = doc.createElementNS(XMLDSIGSpecNS, "ds:EncapsulatedTimeStamp");
            encapsulatedTimeStampElement.setTextContent(Base64.encodeBase64String(timeStampToken.getEncoded()));             
        }
        stsElement.appendChild(encapsulatedTimeStampElement);

        return stsElement;    
    }

    public void addSign (Date signingTime, XmlSignMode mode, final String baseURI, 
                         InputStream srcIS, OutputStream destOS) throws Exception { 
        sign (signingTime, mode, baseURI, srcIS, destOS);
    }    
    
    public void sign (Date signingTime, XmlSignMode mode, final String baseURI,
                      InputStream srcIS, OutputStream destOS) throws Exception {     
        //spdfza System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");      
        EnumMap<Id, String> mapId = new EnumMap<Id, String>(Id.class);        
        XMLSignature xmlSig = null;
        Document doc = null;

        
        // check if need inizialization
        if (isInitialized() == false) {
            throw new Exception ("need initialization");
        }          
        
        // get certificate selected 
        X509Certificate x509Cert = getSignProvider().getX509Certificate();   
        List<X509Certificate> x509CertChain = getCertificateChain();        

        // generate id signer
        mapId.put(Id.Sign, getSignProvider().getCertLabel().replace(" ", "_") + "-" + Long.toHexString(new Date().getTime()));        
        mapId.put(Id.SignedProperties, "SignedProperties-" + mapId.get(Id.Sign)); 
        mapId.put(Id.Reference, "Reference-" + mapId.get(Id.Sign)); 
        mapId.put(Id.SignatureValue, "SignatureValue-" + mapId.get(Id.Sign)); 
        
        // check if initialize security xml
        if (!Init.isInitialized()) {

            // init security xml
            Init.init();
        }

        // get digest algorithm               
        String digestAlg = Constants.ALGO_ID_DIGEST_SHA1;
        if ("SHA1".equals(getProperty(DigestAlgName.getLiteral()))) {
            digestAlg = Constants.ALGO_ID_DIGEST_SHA1;
        }
        else {
            digestAlg = "http://www.w3.org/2001/04/xmlenc#" + getProperty(DigestAlgName.getLiteral()).toLowerCase();
        }            

        // get encryption algorithm            
        String encryptionAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
        if ("RSA".equals(getProperty(EncryptionAlgName.getLiteral()))) {
            if ("SHA1".equals(getProperty(DigestAlgName.getLiteral()))) {
                encryptionAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
            }
            else if ("SHA256".equals(getProperty(DigestAlgName.getLiteral()))) {
                encryptionAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
            }
            else if ("SHA384".equals(getProperty(DigestAlgName.getLiteral()))) {
                encryptionAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384;
            }    
            else if ("SHA512".equals(getProperty(DigestAlgName.getLiteral()))) {
                encryptionAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;
            } 
            else {
                encryptionAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA;
            }                
        }
        else if ("DSA".equals(getProperty(EncryptionAlgName.getLiteral()))) {
            encryptionAlg = XMLSignature.ALGO_ID_SIGNATURE_DSA;
        }
        else {
            throw new Exception ("unknow encryption alg name :" + getProperty(EncryptionAlgName.getLiteral()));
        }
        logger.debug ("Algorithm:" + encryptionAlg);

        // Enveloped
        if (mode == XmlSignMode.Enveloped) {            
            // parsing document
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            doc = dbf.newDocumentBuilder().parse(srcIS);
            Element root = doc.getDocumentElement();              
            
            // create signature object
            xmlSig = new XMLSignature (doc, baseURI, encryptionAlg);
            
            // add sign tags to root tag document
            Element sigElement = xmlSig.getElement();
            root.appendChild(sigElement);
        }
        else if (mode == XmlSignMode.Enveloping) {
            // create new document
            DocumentBuilder builder = DocumentBuilderFactory
                    .newInstance().newDocumentBuilder();  
            doc = builder.newDocument();             
            xmlSig = new XMLSignature(doc, baseURI, encryptionAlg);
            Element root = doc.getDocumentElement();
            
            // create envelope element
            Element sigElement = xmlSig.getElement();            
            Element eEnvelope = doc.createElement("Envelope");
            eEnvelope.appendChild(sigElement);
            doc.appendChild(eEnvelope);             
            
            // parsing original document
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document original = dbf.newDocumentBuilder().parse(srcIS);      
            
            // add origin document
            ObjectContainer obj = new ObjectContainer(doc);                        
            obj.appendChild (doc.importNode(original.getDocumentElement(), true));
            xmlSig.appendObject(obj); 
        }
        else if (mode == XmlSignMode.Detached) {            
            // create new document
            DocumentBuilder builder = DocumentBuilderFactory
                    .newInstance().newDocumentBuilder();  
            doc = builder.newDocument();             
            xmlSig = new XMLSignature(doc, baseURI, encryptionAlg);
            
            // add sign tags
            doc.appendChild(xmlSig.getElement());  
        }
        // set id
        xmlSig.setId (mapId.get(Id.Sign));

        // append signed/unsigned elements
        ObjectContainer objectQualifyingProperties = new ObjectContainer(doc);
        objectQualifyingProperties.appendChild(buildQualifyingProperties (mapId, doc, getEnvelopeSignType(), 
                                                                          digestAlg, signingTime, x509Cert));
        xmlSig.appendObject(objectQualifyingProperties);                 

        // add reference to signed property
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        xmlSig.addDocument("#" + mapId.get(Id.SignedProperties), transforms, digestAlg, null, "http://uri.etsi.org/01903#SignedProperties");       
        
        // add reference to signature 
        transforms = new Transforms(doc);
        XPath2FilterContainer x = XPath2FilterContainer.newInstanceSubtract(doc, "/descendant::ds:" + Constants._TAG_SIGNATURE);             
        transforms.addTransform(Transforms.TRANSFORM_XPATH2FILTER, x.getElement());
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);     
        if (mode == XmlSignMode.Detached) { 
            xmlSig.addDocument(baseURI, transforms, digestAlg, mapId.get(Id.Reference), null); 
        }
        else {
            xmlSig.addDocument("", transforms, digestAlg, mapId.get(Id.Reference), null); 
        }

        // get signed informations
        SignedInfo si = xmlSig.getSignedInfo();
        Element siRootElement = si.getElement(); 

        // calculate digest
        si.generateDigestValues();   
        byte[] toEncrypt = si.getCanonicalizedOctetStream();                                   

        // sign date
        byte [] signature = getSignProvider().sign(toEncrypt);

        // add signature 
        Element[] signatureValueElements = XMLUtils.selectDsNodes(siRootElement, Constants._TAG_SIGNATUREVALUE);
        Element signatureValueElem = signatureValueElements[0];
        while (signatureValueElem.hasChildNodes()) {
            signatureValueElem.removeChild(signatureValueElem.getFirstChild());
        }
        Text txt = siRootElement.getOwnerDocument().createTextNode(new String(Base64.encodeBase64(signature)));
        signatureValueElem.setAttribute("Id", mapId.get(Id.SignatureValue));
        signatureValueElem.setIdAttribute("Id", true); 
        signatureValueElem.appendChild(txt);

        // add certificate
        xmlSig.addKeyInfo(x509Cert);
        
        // add public key
        xmlSig.addKeyInfo(x509Cert.getPublicKey());            

        // create contexts
        Element dsCtx = XMLUtils.createDSctx(doc, "ds", XMLDSIGSpecNS);   
        Element xadesCtx = XMLUtils.createDSctx(doc, "xades", XAdESSpecNS);        
        
        // check if add TimeStampToken
        TimeStampToken timeStampToken = null;
        if (getEnvelopeSignType() == SignType.CAdES_T || 
            getEnvelopeSignType() == SignType.PAdES_T || 
            getEnvelopeSignType() == SignType.XAdES_T) {            

            // get hash from document
            byte []hash = null;
            
            NodeList nlReferences = XPathAPI.selectNodeList(objectQualifyingProperties.getElement(), "//ds:Reference", dsCtx);
            for (int index = 0; index < nlReferences.getLength(); index ++) {
                Element refElement = (Element)nlReferences.item(index);
                if (refElement.getAttribute("URI").equals("")) {
                    Element dvElement = (Element) XPathAPI.selectSingleNode(refElement, "//ds:DigestValue", dsCtx);
                    if (dvElement != null) {
                        hash = Base64.decodeBase64(dvElement.getFirstChild().getNodeValue());
                    }                                                
                }
            }                
            logger.debug("HASH:" + HexString.hexify(hash));

            // add time stamp token
            timeStampToken = TimeStampTokenUtil.getTimeStampToken(new URL(getProperty(TSAURL.getLiteral())), 
                                                                  getProperty(TSAUser.getLiteral()), 
                                                                  getProperty(TSAPassword.getLiteral()), 
                                                                  hash, getDigestAlgOID(), BigInteger.ZERO, 
                                                                  getProperty(SecurityProvider.getLiteral()));
            
            // validate TSA certificate 
            validateTimeStampToken(timeStampToken);           

            // add time stamp token
            Element uspElement = (Element) XPathAPI.selectSingleNode(objectQualifyingProperties.getElement(), "//ds:UnsignedSignatureProperties", dsCtx);
            if (uspElement == null) {
                uspElement = (Element) XPathAPI.selectSingleNode(objectQualifyingProperties.getElement(), "//xades:UnsignedSignatureProperties", xadesCtx);
            }
            if (uspElement != null) {
                uspElement.appendChild(buildSignatureTimeStamp (mapId, doc, getEnvelopeSignType(), timeStampToken));
            }
        }             

        // create output 
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(destOS));                       
    }
    
    public static void main (String []args) throws Exception {
        DOMConfigurator.configure("log4j.xml");        
        
        String pin = "12345678";

        SignProvider signProvider = null; 
        SignHandler signHandler = null;
        Properties prop = new Properties ();        
        if (args.length <= 0) {
            signHandler = new BaseSignHandler("sign");            
            signProvider = new PKCS12Provider("j4ops.p12");
            prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "testCA.ks");             
        }
        else {
            signHandler = new BaseSignHandler(pin);            
            //signProvider = new IaikPKCS11Provider("tokens.xml");
            signProvider = new SunPKCS11Provider("tokens.xml");
            prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "certs.ks");  
        }

        //prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
        //prop.setProperty(EnvelopeSignType.getLiteral(), "XMLDSIG"); 
        
        prop.setProperty(DigestAlgName.getLiteral(), "SHA256"); 
        prop.setProperty(EnvelopeSignType.getLiteral(), "XAdES_BES");                    
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA"); 

        prop.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");  
        
        //prop.setProperty(EnvelopeSignType.getLiteral(), "XAdES_T");       
        prop.setProperty(TSAURL.getLiteral(), "http://timestamping.edelweb.fr/service/tsp");
        
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
        Date date = sdf.parse("120104213756");

        System.out.println ("date:" + date);  
        
        sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
        System.out.println ("date:" + sdf.format(date));  
        
        //date = new Date();
        

        XmlSign xmlSign = new XmlSign (signProvider, signHandler, prop);
        
        File f = new File ("prova.xml");
        FileInputStream fis = new FileInputStream (f);      
        //FileOutputStream fos = new FileOutputStream ("sign.xml");            
        //FileOutputStream fos = new FileOutputStream ("sign_detached.xml");            
        FileOutputStream fos = new FileOutputStream ("prova_enveloped_sign.xml");            
        
        try {
            xmlSign.init();
            //xmlSign.sign(date, XmlSignMode.Enveloped, fis, fos);
            
            //xmlSign.sign(date, XmlSignMode.Detached, f.toURI().toURL().toString(), null, fos);
            xmlSign.sign(date, XmlSignMode.Enveloped, f.toURI().toURL().toString(), fis, fos);
        }
        finally {
            xmlSign.destroy();
        }
        
        fis.close();
        fos.close();
    }     
}
