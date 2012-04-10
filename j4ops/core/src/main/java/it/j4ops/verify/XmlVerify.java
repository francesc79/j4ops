/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.verify;

import static it.j4ops.PropertyConstants.FileKeyStoreTrustedRootCerts;
import static it.j4ops.PropertyConstants.PassKeyStoreTrustedRootCerts;
import it.j4ops.SignType;
import it.j4ops.util.DNParser;
import it.j4ops.verify.bean.SignerInfo;
import it.j4ops.verify.bean.VerifyInfo;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Properties;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.lang.time.DateFormatUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;
import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.implementations.ResolverFragment;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.*;


class ResourceResolverInternal extends ResolverFragment {
    private Logger logger = Logger.getLogger(this.getClass()); 
    private Element siguatureElement = null;
    private Element xadesCtx = null;
    private Element dsCtx = null;
    
    public ResourceResolverInternal (Element siguatureElement, Element dsCtx, Element xadesCtx) {
        this.siguatureElement = siguatureElement;
        this.xadesCtx = xadesCtx;
        this.dsCtx = dsCtx;        
    }
    
    private XMLSignatureInput findId (NodeList nodeList, Attr uri, String baseURI) {
        String uriNodeValue = uri.getNodeValue();
        for (int i = 0; i < nodeList.getLength(); i ++) {
            Element element = (Element)nodeList.item(i); 
            int numAttributes = element.getAttributes().getLength();                
            if (numAttributes > 0) {
                for (int j = 0; j < numAttributes; j++) {
                    String attrName = element.getAttributes().item(j).getNodeName();
                    String attrVal = element.getAttributes().item(j).getNodeValue();
                    if ("id".equalsIgnoreCase(attrName) && uriNodeValue.endsWith(attrVal)) {    
                        logger.debug("found resource " + uriNodeValue);

                        XMLSignatureInput result = new XMLSignatureInput(element);
                        result.setExcludeComments(true);

                        result.setMIMEType("text/xml");
                        if (baseURI != null && baseURI.length() > 0) {
                            result.setSourceURI(baseURI.concat(uri.getNodeValue()));      
                        } else {
                            result.setSourceURI(uri.getNodeValue());      
                        }
                        return result;                                
                    }
                }    
            }                
        }    
        
        return null;
    }
    
    @Override
    public XMLSignatureInput engineResolve(Attr uri, String baseURI) {
        XMLSignatureInput result = null;
        try {
            String uriNodeValue = uri.getNodeValue();
            if (uriNodeValue != null && uriNodeValue.length() > 0 && uriNodeValue.charAt(0) == '#') {
                logger.debug("try to find " + uriNodeValue);

                do {
                    // find signed properties
                    NodeList nlSignedProperty = XPathAPI.selectNodeList(siguatureElement, "//ds:SignedProperties", dsCtx);
                    if (nlSignedProperty == null || nlSignedProperty.getLength() <= 0) {
                        nlSignedProperty = XPathAPI.selectNodeList(siguatureElement, "//xades:SignedProperties", xadesCtx);
                    }                      
                    result = findId (nlSignedProperty, uri, baseURI);
                    if (result != null) {
                        break;
                    }
                    
                    // find object
                    NodeList nlObject = XPathAPI.selectNodeList(siguatureElement, "//ds:Object", dsCtx);
                    result = findId (nlObject, uri, baseURI); 
                    if (result != null) {
                        break;
                    }                    
                }
                while (false);
            }

            if (result == null) {
                result = super.engineResolve(uri, baseURI);
            }
        }
        catch (Exception ex) {
            logger.fatal(ex.toString(), ex);
        }
        
        return result;
    }

}

/**
 *
 * @author fzanutto
 */
public class XmlVerify extends BaseVerify {
    private Logger logger = Logger.getLogger(this.getClass());    
    
    private static final String XMLDSIGSpecNS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XAdESSpecNS = "http://uri.etsi.org/01903/v1.3.2#";    
    
    public XmlVerify (Properties properties) {
        super(properties);
    }
    
    public VerifyInfo verify (InputStream xmlIS) throws Exception {
        VerifyInfo verifyInfo = new VerifyInfo ();   
        
        // check if initialize security xml
        if (!Init.isInitialized()) {

            // init security xml
            Init.init();
        }  
        
        // parsing document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(xmlIS);            

        // create context
        Element dsCtx = XMLUtils.createDSctx(doc, "ds", XMLDSIGSpecNS); 
        Element xadesCtx = XMLUtils.createDSctx(doc, "xades", XAdESSpecNS); 
        
        NodeList nlSiguatures = XPathAPI.selectNodeList(doc, "//ds:Signature", dsCtx);
        for (int index = 0; index < nlSiguatures.getLength(); index ++) {
            Element siguatureElement = (Element)nlSiguatures.item(index);
            
            // Remove any attributes of Signed Info
            Node signInfoNode = XPathAPI.selectSingleNode(siguatureElement, "//ds:SignedInfo", dsCtx);
            int numAttributes = signInfoNode.getAttributes().getLength();
            if (numAttributes > 0) {
                for (int i = 0; i < numAttributes; i++) {
                    String attrName = signInfoNode.getAttributes().item(i).getNodeName();
                    logger.debug(String.format("remove attribute %s from SignedInfo", attrName));
                    signInfoNode.getAttributes().removeNamedItem(attrName);
                }    
            }    
            
            /*
            // find signed properties
            Element signedPropertyElement = (Element) XPathAPI.selectSingleNode(siguatureElement, "//ds:SignedProperties", dsCtx);   
            if (signedPropertyElement == null) {            
                signedPropertyElement = (Element)XPathAPI.selectSingleNode(siguatureElement, "//xades:SignedProperties", xadesCtx);
            }
            if (signedPropertyElement != null) {               
                numAttributes = signedPropertyElement.getAttributes().getLength();                
                if (numAttributes > 0) {
                    for (int i = 0; i < numAttributes; i++) {
                        String attrName = signedPropertyElement.getAttributes().item(i).getNodeName();
                        if ("id".equalsIgnoreCase(attrName)) {    
                            
                            System.out.println ("------------------------------------------FIND:" + signedPropertyElement.getAttributes().item(i).getNodeValue()); //spdfza
                            
                            signedPropertyElement.setIdAttribute(attrName, true);
                        }
                    }    
                }  
            }
            * 
            */

            /*
            // find signed properties
            NodeList nlSignedProperty = XPathAPI.selectNodeList(siguatureElement, "//ds:SignedProperties", dsCtx);
            if (nlSignedProperty == null || nlSignedProperty.getLength() <= 0) {
                nlSignedProperty = XPathAPI.selectNodeList(siguatureElement, "//xades:SignedProperties", xadesCtx);
            }            
            for (int i = 0; i < nlSignedProperty.getLength(); i ++) {
                Element signedPropertyElement = (Element)nlSignedProperty.item(i); 
                numAttributes = signedPropertyElement.getAttributes().getLength();                
                if (numAttributes > 0) {
                    for (int j = 0; j < numAttributes; j++) {
                        String attrName = signedPropertyElement.getAttributes().item(j).getNodeName();
                        if ("id".equalsIgnoreCase(attrName)) {    
                            
                            System.out.println ("-----------------------------------------------FIND:" + signedPropertyElement.getAttributes().item(j).getNodeValue()); //spdfza
                            
                            signedPropertyElement.setIdAttribute(attrName, true);
                        }
                    }    
                }                
            } 
            */
            
            
            // get signature element
            XMLSignature xmlSig = new XMLSignature(siguatureElement, "");
            xmlSig.setFollowNestedManifests(true); 
            xmlSig.addResourceResolver(new ResourceResolverInternal (siguatureElement, dsCtx, xadesCtx));
            

            // get certificate element
            Element certElement = 
                (Element) XPathAPI.selectSingleNode(siguatureElement, "//ds:X509Certificate", dsCtx);   
            if (certElement != null) {
                byte [] cert = Base64.decode(certElement.getFirstChild().getNodeValue());
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate x509Cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream (cert));

                // check signature
                if (xmlSig.checkSignatureValue(x509Cert) == true) {

                    // create signer informations                     
                    SignerInfo signerInfo = new SignerInfo ();
                    signerInfo.setCounterSignature(false);
                    signerInfo.setSignerInformation(null);
                    signerInfo.setX509Cert(x509Cert);
                    signerInfo.setAuthor(DNParser.parse(x509Cert.getSubjectDN().toString(), "CN"));
                    signerInfo.setLevel(0);
                    
                    // get signing time
                    Element signTimeElement = (Element) XPathAPI.selectSingleNode(siguatureElement, "//ds:SigningTime", dsCtx);   
                    if (signTimeElement == null) {
                        signTimeElement = (Element) XPathAPI.selectSingleNode(siguatureElement, "//xades:SigningTime", xadesCtx); 
                    }
                    if (signTimeElement != null) {
                        String pattern = DateFormatUtils.ISO_DATETIME_TIME_ZONE_FORMAT.getPattern();
                        signerInfo.setDateSign(DateUtils.parseDate(signTimeElement.getFirstChild().getNodeValue(), new String[] { pattern }));
                    }
                    
                    // check signed type
                    if (XPathAPI.selectSingleNode(siguatureElement, "//xades:SigningCertificate", xadesCtx) != null) {
                        signerInfo.setSignType(SignType.XAdES_BES);
                        if (XPathAPI.selectSingleNode(siguatureElement, "//xades:SignatureTimeStamp", xadesCtx) != null) {
                            signerInfo.setSignType(SignType.XAdES_T);
                        }
                    }
                    else {
                        signerInfo.setSignType(SignType.XMLDSIG);
                    }
                    verifyInfo.addSignerInfo(signerInfo);                    
                                        
                    // validate certificate
                    validateCertificate(signerInfo);                    
                    
                    logger.info ("Verified!");         
                    logger.info (String.format("SignType:%s", signerInfo.getSignType()));                      
                    logger.info (String.format("DateSign:%s", new SimpleDateFormat("dd-MM-yyyy hh:mm:ss").format(signerInfo.getDateSign())));  
                    logger.info (String.format("Author:%s", signerInfo.getAuthor()));  
                    logger.info (String.format("isCounterSignature:%b", signerInfo.isCounterSignature())); 
                }     
                else {
                    logger.fatal ("Sign not verified");                
                    throw new Exception ("Sign not verified");            
                }

                //  Remove the signature
                siguatureElement.getParentNode().removeChild(siguatureElement); 
            }            
        }
        
        return verifyInfo;
    }
    
    
    public static void main (String []args) throws Exception {
        DOMConfigurator.configure("log4j.xml");
        Properties prop = new Properties ();      
        prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "certs.ks"); 
        //prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "testCA.ks"); 
        prop.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");
        XmlVerify xmlVerify = new XmlVerify (prop);
        
        FileInputStream fis = null;
        
        try {
            fis = new FileInputStream ("prova_addsign_enveloping.xml");
            VerifyInfo vi = xmlVerify.verify(fis);            
            System.out.println (String.format("count signs:%d", vi.getCountSigns()));
        }
        finally {
            try {
                if (fis != null) {
                    fis.close();
                    fis = null;
                }
            }
            catch (IOException ex) {}         
        }
        
    }     
}
