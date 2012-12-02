/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.token;

import java.io.*;
import java.util.ArrayList;
import java.util.Properties;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 *
 * @author fzanutto
 */
public class TokenRecognize {
    private static Logger logger = LoggerFactory.getLogger(TokenRecognize.class);
    
    
    private static class Token {
        private String atrMask;
        private String driver;
        private String description;

        public String getAtrMask() {
            return atrMask;
        }

        public void setAtrMask(String atrMask) {
            this.atrMask = atrMask;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getDriver() {
            return driver;
        }

        public void setDriver(String driver) {
            this.driver = driver;
        }
        
        public void parse (Element element) {
            NodeList nodeLst = element.getChildNodes();
            for (int index = 0; index < nodeLst.getLength(); index ++) {
                Node n = nodeLst.item(index);
                if (n.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                } 
                Element e = (Element)n;          

                // verifico di che tag si tratta
                if (e.getTagName().equalsIgnoreCase("atr_mask")) {  
                    atrMask = e.getFirstChild().getNodeValue();
                }
                else if (e.getTagName().equalsIgnoreCase("driver")) {  
                    driver = e.getFirstChild().getNodeValue();
                }
                else if (e.getTagName().equalsIgnoreCase("description")) {  
                    description = e.getFirstChild().getNodeValue();
                }                
            }        
        }
        
        public void build (Document doc, Element parent) {
            Element element = doc.createElement("token");
            parent.appendChild(element);
            
            Element eAtr = doc.createElement("atr_mask");
            eAtr.appendChild(doc.createTextNode(atrMask==null?"":atrMask));
                        
            Element eDriver = doc.createElement("driver");
            eDriver.appendChild(doc.createTextNode(driver==null?"":driver));
            
            Element eDescription = doc.createElement("description"); 
            eDescription.appendChild(doc.createTextNode(description==null?"":description));            

            element.appendChild(eAtr);
            element.appendChild(eDriver);
            element.appendChild(eDescription);            
        }        
        
    } 
    
    public static TokenInfo recognize (String file, TokenInfo cardInfo) throws Exception {
        ArrayList<Token> lstTokens = new ArrayList<Token>();        
        InputStream is = null;
        try {            
            is = TokenRecognize.class.getClassLoader().getResourceAsStream (file);
            if (is == null) {            
                is = new FileInputStream (file);
            }

            // parsing files
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder parser = factory.newDocumentBuilder();
            factory.setValidating(false);
            factory.setIgnoringComments(true);
            parser.setEntityResolver(new EntityResolver() {
                @Override
                public InputSource resolveEntity(String publicId, String systemId)
                        throws SAXException, IOException {
                    return new InputSource(new StringReader(""));
                }
            });                                    
            Document doc = parser.parse(is);        
            Element rootElement = doc.getDocumentElement();
            NodeList nodeLst = rootElement.getChildNodes();
            for (int index = 0; index < nodeLst.getLength(); index ++) {
                Node n = nodeLst.item(index);
                if (n.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                } 
                Element e = (Element)n;          
                if (e.getTagName().equalsIgnoreCase("token")) {  
                    Token token = new Token ();
                    token.parse(e);
                    lstTokens.add (token);
                }
            }            
        }
        finally {
            try {
                if (is != null) {
                    is.close();
                    is = null;
                }
            }
            catch (Exception ex){}
        }
        
        for (Token token : lstTokens) {
            logger.debug("recognizing token match atr with:" + token.getAtrMask());
            if (cardInfo.getAtr().matches(token.getAtrMask().toUpperCase())) {
                logger.debug("recognized token use driver:" + token.getDriver());
                cardInfo.setDriver(token.getDriver());
                cardInfo.setDriverDescription(token.getDescription());
                return cardInfo;
            }            
        }
        return null;
    }
    
    public static void buildDefault ()  throws Exception {
        ArrayList<Token> lstTokens = new ArrayList<Token>();
                
        Token token = new Token ();
        token.setAtrMask("3bfc9800ffc11031fe55c803496e666f63616d65726528");
        token.setDriver("SI_PKCS11");
        token.setDescription("Siemens 140/150");   
        lstTokens.add(token);
        
        token = new Token ();
        token.setAtrMask("3bff1100ff81318055006802001010494e43525950544f001a");
        token.setDriver("ipmpki32");
        token.setDescription("ST INCARD INCRYPTO V1 32K");   
        lstTokens.add(token);
                
        token = new Token ();
        token.setAtrMask("3bf49800ffc11031fe554d346376b4");
        token.setDriver("ipmpki32");
        token.setDescription("CryptoVision");   
        lstTokens.add(token);

        token = new Token ();
        token.setAtrMask("3bff1800ff8131fe55006b0209020001..01434e53..3180..");
        token.setDriver("bit4ipki");
        token.setDescription("incrypto34v2");   
        lstTokens.add(token);       
        
        token = new Token ();
        token.setAtrMask("3bf4180002c10a31fe5856346376c5");
        token.setDriver("cmp11");
        token.setDescription("Token EUTRON CARDOS M4.3B - Charismatics");   
        lstTokens.add(token);
        
        token = new Token ();
        token.setAtrMask("3bff1800ff8131fe55006b0209030301..01434e53..3180..");
        token.setDriver("bit4ipki");
        token.setDescription("Touch Sign con chiavi DS a 2048 bits");   
        lstTokens.add(token);            

        //CNS        
        token = new Token ();
        token.setAtrMask("3bff1800008131fe45006b0405010001..01434e53..3180..");
        token.setDriver("bit4opki");
        token.setDescription("CNS Oberthur");   
        lstTokens.add(token); 
        
        token = new Token ();
        token.setAtrMask("3bff1800ffc10a31fe55006b0508c80501..01434e53..3180..");
        token.setDriver("cnsPKCS11");
        token.setDescription("CNS Siemens");   
        lstTokens.add(token);         

        token = new Token ();
        token.setAtrMask("3bff1800ffc10a31fe55006b0508c80501..02485043..3180..");
        token.setDriver("sissP11");
        token.setDescription("SISS");   
        lstTokens.add(token);         
               
		// creo il document
        DocumentBuilder builder = DocumentBuilderFactory
                .newInstance().newDocumentBuilder();  
        Document doc =  builder.newDocument();    		
		Element rootElement = doc.createElement("tokens");
		doc.appendChild(rootElement);  
        
        for (Token t : lstTokens) {
            t.build(doc, rootElement);
        }
        
        FileOutputStream fos = null;        
        try {
            fos = new FileOutputStream ("tokens.xml");
            TransformerFactory transfac = TransformerFactory.newInstance();
            Transformer trans = transfac.newTransformer();

            StreamResult result = new StreamResult(fos);
            DOMSource source = new DOMSource(doc);
            trans.transform(source, result);
        }
        finally {
            try {
                if (fos != null) {
                    fos.close();
                    fos = null;
                }
            }
            catch (Exception ex) {}
        }    
    }
    
    
    public static void main (String []args) throws Exception {
        buildDefault ();
    }
}
