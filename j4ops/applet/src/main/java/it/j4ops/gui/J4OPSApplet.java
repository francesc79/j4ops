/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.gui;

import it.j4ops.CmsSignMode;
import static it.j4ops.PropertyConstants.DigestAlgName;
import static it.j4ops.PropertyConstants.EnvelopeSignType;
import it.j4ops.SignType;
import it.j4ops.XmlSignMode;
import it.j4ops.sign.CmsSign;
import it.j4ops.sign.PdfSign;
import it.j4ops.sign.XmlSign;
import it.j4ops.sign.provider.SunPKCS11Provider;
import java.applet.Applet;
import java.awt.Color;
import java.io.*;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.Properties;
import javax.swing.SwingUtilities;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.log4j.xml.DOMConfigurator;

/**
 *
 * @author zanutto
 */
public class J4OPSApplet extends javax.swing.JApplet {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    public static final int TIMEOUT_POST = 60000;  
    public static final int TIMEOUT_GET = 60000;       
    public static final String PARAM_TARGET = "Target";    
    public static final String PARAM_ACTION = "Action";
    public static final String PARAM_SIGN_MODE = "SignMode";    
    public static final String PARAM_XML_SIGN_MODE = "XmlSignMode";      
    public static final String PARAM_DOCUMENT_URL = "DocumentURL";  
    public static final String PARAM_POST_CERTIFICATE_URL = "PostCertificateURL";  
    public static final String PARAM_POST_DOCUMENT_URL = "PostDocumentURL"; 
    public static final String PARAM_BACKGROUND_COLOR = "BackgroundColor";
    public static final String PARAM_COOKIE = "Cookie";

    public static final String PARAM_RESP_DOCUMENT_URL = PARAM_DOCUMENT_URL;    
    public static final String PARAM_RESP_POST_DOCUMENT_URL = PARAM_POST_DOCUMENT_URL;        
    public static final String PARAM_RESP_ERROR = "Error";    
    public static final String PARAM_RESP_X509CERT = "X509Cert";  
    public static final String HEADER_RESP_OPER = "Oper";      
    public static final String HEADER_RESP_ACTION = "Action"; 
    
    public static final String ACTION_SIGN = "SIGN";
    public static final String ACTION_ADD_SIGN = "ADD_SIGN";
    

    private Thread thApplet = null;
    private String[][] info = null;    
    private AppletHendler appletHendler = null;

    
    public class AppletHendler implements Runnable {
        private final Logger logger = LoggerFactory.getLogger(this.getClass());
        private X509Certificate x509Cert = null;        
        private CmsSign cmsSign = null;
        private PdfSign pdfSign = null;
        private XmlSign xmlSign = null;
        private Properties prop = null;
        private Applet owner = null;
        

        public void init (Applet owner, Properties prop) {
            this.owner = owner;
            this.prop = prop;            
        }
                      
        private String send (HttpMethod method, int timeout) throws Exception { 
            logger.debug("send post to url:" + method.getURI());  

            HttpClientParams params = new HttpClientParams();
            if (timeout > 0) {
                params.setSoTimeout(timeout);
            }
            HttpClient httpClient = new HttpClient(params);        

            if (prop.getProperty (PARAM_COOKIE) != null && !"".equals(prop.getProperty (PARAM_COOKIE))) {
                method.setRequestHeader ("Cookie", prop.getProperty (PARAM_COOKIE));
            }            
            
            int returnCode = httpClient.executeMethod (method);
            if (returnCode != HttpStatus.SC_OK) {
                throw new Exception ("Error on calling servlet error code:" + returnCode);
            }

            return method.getResponseBodyAsString();        
        }

        private String sendPOST (String url, int timeout, X509Certificate x509Cert) throws Exception {
            PostMethod method = new PostMethod (url);         
            String ret = null;
            method.setRequestHeader (HEADER_RESP_OPER, "SendCertificate");
            method.setRequestHeader (HEADER_RESP_ACTION, prop.getProperty (PARAM_ACTION));
            method.addParameter (PARAM_RESP_DOCUMENT_URL, prop.getProperty (PARAM_DOCUMENT_URL));      
            method.addParameter (PARAM_RESP_POST_DOCUMENT_URL, prop.getProperty (PARAM_POST_DOCUMENT_URL));                              
            method.addParameter (PARAM_RESP_X509CERT, new String (Base64.encodeBase64(x509Cert.getEncoded(), false)));      
            try {
                ret = send (method, timeout);
            } finally {
                method.releaseConnection();
            }        
            return ret;
        }

        private String sendPOST (String url, int timeout, String error) throws Exception {
            PostMethod method = new PostMethod (url);         
            String ret = null;
            method.setRequestHeader(HEADER_RESP_OPER, "SendError");
            method.setRequestHeader (HEADER_RESP_ACTION, prop.getProperty (PARAM_ACTION));   
            method.addParameter (PARAM_RESP_DOCUMENT_URL, prop.getProperty (PARAM_DOCUMENT_URL));      
            method.addParameter (PARAM_RESP_POST_DOCUMENT_URL, prop.getProperty (PARAM_POST_DOCUMENT_URL));               
            method.addParameter(PARAM_RESP_ERROR, error);      
            try {
                ret = send (method, timeout);
            } finally {
                method.releaseConnection();
            }        
            return ret;
        }   

        private String sendPOST (String url, int timeout, InputStream is) throws Exception {
            PostMethod method = new PostMethod (url); 
            String ret = "";

            method.setRequestHeader(HEADER_RESP_OPER, "SendSignedData");
            method.setRequestHeader (HEADER_RESP_ACTION, prop.getProperty (PARAM_ACTION));             
            method.setRequestEntity(new InputStreamRequestEntity (is));
            method.setRequestHeader ("Content-type", "application/octet-stream");

            try {
                ret = send (method, timeout);
            } finally {
                method.releaseConnection();
            }        
            return ret;
        }
        
        private byte [] readAll (InputStream inStr) throws IOException {
            ByteArrayOutputStream outStr = new ByteArrayOutputStream();
            byte[] bs = new byte[1024];
            int numRead;
            while ((numRead = inStr.read(bs, 0, bs.length)) >= 0) {
                outStr.write(bs, 0, numRead);
            }        
            return outStr.toByteArray();
        }        
        
        private byte[] sendGET (String url, int timeout) throws Exception {  
            GetMethod method = new GetMethod (url); 
            byte []ret = null;
            try {
                send (method, timeout);
                ret = readAll(method.getResponseBodyAsStream());
            } finally {
                method.releaseConnection();
            } 
            
            return ret;
        }
        
        
        private void pasingResponse (String response) throws Exception {
            logger.debug("response to post document:" + response);

            BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(response.getBytes())));
            String line = null;
            while ((line = br.readLine()) != null) {
                if (line.indexOf("=") > 0) {
                    String key = line.substring(0, line.indexOf("="));
                    String value = line.substring(line.indexOf("=") + 1);
                    logger.debug(String.format("set property %s value %s", key, value));
                    prop.setProperty (key, value);                    
                }
            }
        }

        private void sendPOSTAndParsingResponse (String url, int timeout, String error) throws Exception {
            String response = sendPOST (url, timeout, error);
            if (response != null) { 
                pasingResponse (response);
            }            
        }        
        
        private void sendPOSTAndParsingResponse (String url, int timeout, InputStream is) throws Exception {
            String response = sendPOST (url, timeout, is);
            if (response != null) { 
                pasingResponse (response);
            }       
        }      
        
        private void sendPOSTAndParsingResponse (String url, int timeout, X509Certificate x509Cert) throws Exception {
            String response = sendPOST (url, timeout, x509Cert);
            if (response != null) { 
                pasingResponse (response);
            }       
        }        
        
        private void _sign () throws Exception {  
            
            //------------------------------------------------------------------
            // Init
            //            
            
            // get sign type
            SignType signType = SignType.valueOf (prop.getProperty(EnvelopeSignType.getLiteral()));
            
            // create signer provider
            SunPKCS11Provider signProvider = new SunPKCS11Provider (prop.getProperty(ConfigDialog.FileConfigPKCS11Tokens));

            // create signer handler
            GuiSignHandler signHandler = new GuiSignHandler (SwingUtilities.windowForComponent (owner));

            // show message
            J4OPSApplet.this.setMessage("Init j4ops");
            
            switch (signType) {
                case Pkcs7:
                case CAdES_BES:
                case CAdES_T:

                    if (signType == SignType.Pkcs7) {
                        prop.setProperty (DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    cmsSign = new CmsSign (signProvider, signHandler, prop);  
                    x509Cert = cmsSign.init();  
                    break;

                case PDF:
                case PAdES_BES:
                case PAdES_T:

                    if (signType == SignType.PDF) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }                                         
                    pdfSign = new PdfSign (signProvider, signHandler, prop); 
                    x509Cert = pdfSign.init();
                    break;                                        

                case XMLDSIG:
                case XAdES_BES:
                case XAdES_T:

                    if (signType == SignType.XMLDSIG) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    xmlSign = new XmlSign (signProvider, signHandler, prop); 
                    x509Cert = xmlSign.init();
                    break;              
            }
            
            // show message
            J4OPSApplet.this.setMessage("Send certificate selected");

            // check if send certificate
            if (x509Cert != null && prop.getProperty(PARAM_POST_CERTIFICATE_URL) != null) {
                sendPOSTAndParsingResponse (prop.getProperty(PARAM_POST_CERTIFICATE_URL), TIMEOUT_POST, x509Cert);
            }            

            //------------------------------------------------------------------
            // Sign
            //
            
            do {
                // check if have document url
                String documentURL = prop.getProperty(PARAM_DOCUMENT_URL);
                if (documentURL == null || documentURL.length() <= 0) {
                    
                    // destroy resources
                    _destroy ();

                    // go to new url
                    logger.debug(String.format ("show document url:%s target:%s", prop.getProperty(PARAM_POST_DOCUMENT_URL), prop.getProperty(PARAM_TARGET)));
                    owner.getAppletContext().showDocument(new URL(prop.getProperty(PARAM_POST_DOCUMENT_URL)), prop.getProperty(PARAM_TARGET));                     
                    break;
                }                
                
                // show message
                J4OPSApplet.this.setMessage("Sign document: " +  prop.getProperty(PARAM_DOCUMENT_URL));
                
                // get sign type                  
                logger.debug (String.format("SignType:%s Action:%s", signType, prop.getProperty (PARAM_ACTION))); 

                ByteArrayOutputStream baos = new ByteArrayOutputStream (); 
                InputStream is = null;                          

                logger.debug ("get document to sign:" + prop.getProperty(PARAM_DOCUMENT_URL));

                // get document
                is = new ByteArrayInputStream (sendGET (prop.getProperty(PARAM_DOCUMENT_URL), TIMEOUT_GET));                
                Date signDate = new Date();

                switch (signType) {
                    case Pkcs7:
                    case CAdES_BES:
                    case CAdES_T:

                        CmsSignMode cmsSignMode = CmsSignMode.valueOf(prop.getProperty(PARAM_SIGN_MODE));
                        if (prop.getProperty (PARAM_ACTION).equalsIgnoreCase(ACTION_SIGN)) {
                            cmsSign.sign (signDate, cmsSignMode, is, baos);  
                        }
                        else if (prop.getProperty (PARAM_ACTION).equalsIgnoreCase(ACTION_ADD_SIGN)) {
                            cmsSign.addSign (signDate, cmsSignMode, is, baos);  
                        }
                        break;

                    case PDF:
                    case PAdES_BES:
                    case PAdES_T:

                        if (prop.getProperty (PARAM_ACTION).equalsIgnoreCase(ACTION_SIGN)) {
                            pdfSign.sign (signDate, is, null, baos);
                        }
                        else if (prop.getProperty (PARAM_ACTION).equalsIgnoreCase(ACTION_ADD_SIGN)) {
                            pdfSign.addSign (signDate, is, null, baos);                        
                        }                        
                        break;                                        

                    case XMLDSIG:
                    case XAdES_BES:
                    case XAdES_T:

                        XmlSignMode xmlSignMode = XmlSignMode.valueOf(prop.getProperty(PARAM_XML_SIGN_MODE, "Enveloped"));                    
                        String baseURI = "";
                        if (prop.getProperty (PARAM_ACTION).equalsIgnoreCase(ACTION_SIGN)) {
                            xmlSign.sign (signDate, xmlSignMode, baseURI, is, baos);
                        }
                        else if (prop.getProperty (PARAM_ACTION).equalsIgnoreCase(ACTION_ADD_SIGN)) {  
                            xmlSign.addSign (signDate, xmlSignMode, baseURI, is, baos);
                        }                  
                        break;              
                }        

                // show message
                J4OPSApplet.this.setMessage("Upload signed document to:" + prop.getProperty(PARAM_POST_DOCUMENT_URL));                
                
                // send data and parsing response
                sendPOSTAndParsingResponse (prop.getProperty(PARAM_POST_DOCUMENT_URL), TIMEOUT_POST, new ByteArrayInputStream (baos.toByteArray()));             
            }
            while (true);
        }   
        
        private void _destroy () throws Exception { 
            
            try {
                if (cmsSign != null) {
                    cmsSign.destroy();
                    cmsSign = null;
                }
            }
            catch (Exception ex) {}            
            try {
                if (pdfSign != null) {
                    pdfSign.destroy();
                    pdfSign = null;
                }
            }
            catch (Exception ex) {}     
            try {
                if (xmlSign != null) {
                    xmlSign.destroy();
                    xmlSign = null;
                }
            }
            catch (Exception ex) {}                   
        }         
        
        @Override
        public void run() {
            
            AccessController.doPrivileged (new PrivilegedAction() {
                @Override
                public Object run() {             
                    try {                                    
                       _sign();
                    }
                    catch (Exception ex) {
                        logger.error(ex.toString(), ex);
                        try {
                            _destroy();
                        }
                        catch (Exception e) {
                            logger.error(e.toString(), e);
                        }
                        try {
                            // show message
                            J4OPSApplet.this.setMessage(ex.toString());                       

                            // send error
                            sendPOSTAndParsingResponse (prop.getProperty(PARAM_POST_DOCUMENT_URL), TIMEOUT_POST, ex.toString());
                            String documentURL = prop.getProperty(PARAM_DOCUMENT_URL);
                            if ((documentURL == null || documentURL.length() <= 0)) {     
                                // go to new url
                                logger.debug(String.format ("show document url:%s target:%s", prop.getProperty(PARAM_DOCUMENT_URL), prop.getProperty(PARAM_TARGET)));
                                owner.getAppletContext().showDocument(new URL(prop.getProperty(PARAM_POST_DOCUMENT_URL)), prop.getProperty(PARAM_TARGET));                                 
                            }           
                        }
                        catch (Exception e) {
                           logger.error(e.toString(), e);
                        }
                    }  
                    return null;
                }
            });
        }
    }
    
    public static Properties getDefault () {
        Properties prop = new Properties ();        
        for (Map.Entry<Object, Object> entry : ConfigDialog.getDefault().entrySet()) {
            prop.setProperty((String)entry.getKey(), (String)entry.getValue());
        }     
        prop.setProperty(PARAM_TARGET, "");         
        prop.setProperty(PARAM_ACTION, "SIGN");         
        prop.setProperty(PARAM_SIGN_MODE, "Attached");   
        prop.setProperty(PARAM_XML_SIGN_MODE, "Enveloped"); 
        prop.setProperty(PARAM_DOCUMENT_URL, "");
        prop.setProperty(PARAM_POST_CERTIFICATE_URL, ""); 
        prop.setProperty(PARAM_POST_DOCUMENT_URL, "");      
        prop.setProperty(PARAM_BACKGROUND_COLOR, "000000");     
        prop.setProperty(PARAM_COOKIE, "");
        return prop;
    }     
    
    
    public J4OPSApplet () {
        ArrayList<Object> listKeys = new ArrayList<Object>();
        listKeys.addAll(J4OPSApplet.getDefault().keySet());
        info = new String[listKeys.size()][];
        for (int i = 0;i < listKeys.size(); i ++) {
            info[i] = new String []{listKeys.get(i).toString(), "", ""};
        }
        appletHendler = new AppletHendler ();                    
    }      
    
    @Override
    public void init() { 
        
        // check if enable log4j
        URL url = getClass().getResource("/log4j.xml");
        if (url != null) {
            DOMConfigurator.configure (url);        
        }
        
        // get properties
        Properties prop = new Properties (J4OPSApplet.getDefault());
        for (int i = 0; i < info.length; i ++) {
            String val = this.getParameter(info[i][0]);
            if (val != null) {
                prop.setProperty(info[i][0], val);
            }
        }        
        
        // show all parameters loaded
        for (Map.Entry<Object, Object> entry : prop.entrySet()) {
            logger.debug (String.format("property key:%s value:%s", (String)entry.getKey(), (String)entry.getValue()));
        }      
        
        // init handler
        appletHendler.init(this, prop);

        /*
         * Set the Nimbus look and feel
         */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /*
         * If Nimbus (introduced in Java SE 6) is not available, stay with the
         * default look and feel. For details see
         * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(J4OPSApplet.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(J4OPSApplet.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(J4OPSApplet.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(J4OPSApplet.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        // set background color
        setBackground (Color.decode(prop.getProperty(PARAM_BACKGROUND_COLOR)));        
        
        /*
         * Create and display the applet
         */
        try {
            java.awt.EventQueue.invokeAndWait (new Runnable() {

                @Override
                public void run() {
                    initComponents();
                }
            });
        } catch (Exception ex) {
            logger.error(ex.toString(), ex);
        }
    }

    @Override
    public void start() {  
        thApplet = new Thread (appletHendler);
        thApplet.start();        
    }    
    
    @Override
    public void stop() {          
        try {
            thApplet.interrupt();
            thApplet.join();
        }
        catch (Exception ex) {}
    } 
    
    @Override
    public void destroy() {      
    }      
    
    @Override
    public String getAppletInfo() {
        return "J4OPS Applet";
    }

    @Override
    public String[][] getParameterInfo() {
        return info;
    }    
    
    private void setMessage (final String msg) {
        try {
            java.awt.EventQueue.invokeAndWait (new Runnable() {

                @Override
                public void run() {
                    if (jlabMessage != null) {
                        jlabMessage.setText(msg);
                    }
                }
            });
        } catch (Exception ex) {
            logger.error(ex.toString(), ex);
        }    
    }
    
    /**
     * This method is called from within the init() method to initialize the
     * form. WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jlabMessage = new javax.swing.JLabel();

        jlabMessage.setFont(new java.awt.Font("Ubuntu", 1, 12)); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jlabMessage, javax.swing.GroupLayout.DEFAULT_SIZE, 349, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(25, 25, 25)
                .addComponent(jlabMessage, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(23, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jlabMessage;
    // End of variables declaration//GEN-END:variables
}
