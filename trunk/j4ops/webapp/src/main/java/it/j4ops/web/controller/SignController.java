package it.j4ops.web.controller;

import it.j4ops.PropertyConstants;
import it.j4ops.util.DERUtil;
import it.j4ops.util.DNParser;
import it.j4ops.util.X509Util;
import it.j4ops.web.model.Configuration;
import it.j4ops.web.model.Sign;
import it.j4ops.web.model.Document;
import it.j4ops.web.util.PDFUtil;
import it.j4ops.web.validator.SignFormValidator;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.URIUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.WebUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import static it.j4ops.gui.J4OPSApplet.*;
import static it.j4ops.web.config.WebMvcConfig.*;

@Controller
@SessionAttributes({"signList", "signIndex", "properties", "addSignInfo"})
public class SignController implements ServletContextAware {

    private ServletContext servletContext;

    @Autowired
    private Configuration config;

    @InitBinder("sign")
    public void initBinder(WebDataBinder dataBinder) {
        dataBinder.setValidator(new SignFormValidator());
    }

    @RequestMapping(value="/sign.htm", method= RequestMethod.POST)
    public ModelAndView sign (HttpServletRequest request, @Validated Sign sign, BindingResult result) throws Exception {

        ModelAndView modelAndView = new ModelAndView("sign");
        if (result.hasErrors()) {
            modelAndView.setViewName("index");
            return modelAndView;
        }
        else {
            List<String> signList = new ArrayList<String>();
            Integer signIndex = 0;

            String urlBase = request.getScheme () + "://" + request.getServerName () + ":" + request.getServerPort () + request.getContextPath ();
            String documentURL = urlBase + DIR_DOCUMENTS;
            String postDocumentURL = urlBase + "/signed.htm";
            if (sign.getDocumentList() != null) {
                for (Document doc : sign.getDocumentList()) {
                    if (doc.isChecked()) {
                        signList.add(doc.getName());
                    }
                }
            }

            if (signList.size() <= 0) {
                modelAndView.setViewName("index");
                modelAndView.addObject("error", "No document selected");
                return modelAndView;
            }

            // get configuration
            Properties properties = config.getProperties();
            properties.setProperty(PropertyConstants.EnvelopeSignType.getLiteral(), sign.getEnvelopeSignType());
            properties.setProperty(PARAM_SIGN_MODE, sign.getSignMode());
            properties.setProperty(PARAM_XML_SIGN_MODE, sign.getXmlSignMode());

            modelAndView.addObject("signList", signList);
            modelAndView.addObject("signIndex", signIndex);
            modelAndView.addObject("properties", properties);
            modelAndView.addObject("addSignInfo", sign.isAddSignInfo());
            modelAndView.addObject("documentURL", documentURL + URIUtil.encodeQuery(signList.get(signIndex)));
            modelAndView.addObject("postDocumentURL", postDocumentURL);

            return modelAndView;
        }
    }

    @RequestMapping(value="/signed.htm", method= RequestMethod.POST)
    public ModelAndView signed (HttpServletRequest request,
                                @RequestHeader(HEADER_RESP_OPER) String oper,
                                @ModelAttribute(PARAM_RESP_POST_DOCUMENT_URL) String postDocumentURL,
                                @ModelAttribute(PARAM_RESP_DOCUMENT_URL) String documentURL,
                                @RequestParam(required = false, value=PARAM_RESP_X509CERT) String x509CertB64,
                                @RequestParam(required = false, value=PARAM_RESP_ERROR) String error,
                                SessionStatus sessionStatus,
                                BindingResult result) throws Exception {

        if (result.hasErrors()) {
            for (ObjectError e : result.getAllErrors()) {
                System.out.println ("error:" + e.toString());
            }
        }

        System.out.println ("processing request upload remote address:" + request.getRemoteAddr());
        Enumeration<String> eParams = request.getParameterNames();
        while (eParams.hasMoreElements()) {
            String property = eParams.nextElement();
            System.out.println (String.format("property:%s value:%s", property, request.getParameter(property)));
        }

        @SuppressWarnings("unchecked")
        List<String> signList = (List<String>) WebUtils.getSessionAttribute(request, "signList");
        Integer signIndex = (Integer)WebUtils.getSessionAttribute(request, "signIndex");
        Properties properties = (Properties)WebUtils.getSessionAttribute(request, "properties");
        Boolean addSignInfo = (Boolean)WebUtils.getSessionAttribute(request, "addSignInfo");

        String envelopeSignType = (String)properties.get(PropertyConstants.EnvelopeSignType.getLiteral());
        String pathBase = servletContext.getRealPath("");
        String urlBase = request.getScheme () + "://" + request.getServerName () + ":" + request.getServerPort () + request.getContextPath ();
        try {
            if ("SendError".equalsIgnoreCase(oper)) {
                postDocumentURL = urlBase + "/index.htm?error=" + URIUtil.encodeQuery (error);
                documentURL = "";
            }
            else if ("SendCertificate".equalsIgnoreCase(oper)) {

                X509Certificate x509Cert = X509Util.toX509Certificate(Base64.decodeBase64(x509CertB64), null);
                if (addSignInfo == true) {
                    String text = "Document signed by:" + DNParser.parse(x509Cert.getSubjectDN().toString(), "CN");
                    for (int index = 0; index < signList.size(); index ++) {
                        File tmp = File.createTempFile (signList.get(index) + "#", ".tmp", new File (pathBase + DIR_DOCUMENTS));
                        FileInputStream fis = null;
                        FileOutputStream fos = null;
                        try {
                            fis = new FileInputStream (pathBase + DIR_DOCUMENTS + signList.get(index));
                            fos = new FileOutputStream (tmp.getAbsolutePath());
                            PDFUtil.changePDF(fis, fos, text);
                        }
                        finally {
                            try {
                                if (fis != null) {
                                    fis.close();
                                    fis = null;
                                }
                            }
                            catch (Exception e){}

                            try {
                                if (fos != null) {
                                    fos.close();
                                    fos = null;
                                }
                            }
                            catch (Exception e){}
                        }
                        signList.set(index, tmp.getName());
                    }

                    documentURL = urlBase + DIR_DOCUMENTS + URIUtil.encodeQuery(signList.get (signIndex));
                }
            }
            else if ("SendSignedData".equalsIgnoreCase(oper)) {

                String fileName = signList.get (signIndex);
                FileOutputStream fos = null;
                try {
                    // check if temp file
                    if (fileName.endsWith(".tmp")) {
                        new File (pathBase + DIR_DOCUMENTS + fileName).delete();
                        fileName = fileName.substring(0, fileName.indexOf("#"));
                    }

                    fileName = pathBase + DIR_DOCUMENTS + fileName;
                    fileName = fileName.substring(0, fileName.lastIndexOf("."));
                    if (envelopeSignType != null && envelopeSignType.startsWith("CAdES")) {
                        fileName += "_sign.p7m";
                    }
                    else if (envelopeSignType != null && envelopeSignType.startsWith("PAdES")) {
                        fileName += "_sign.pdf";
                    }
                    else if (envelopeSignType != null && envelopeSignType.startsWith("XAdES")) {
                        fileName += "_sign.xml";
                    }

                    fos = new FileOutputStream (fileName);
                    fos.write (DERUtil.streamToByteArray(request.getInputStream()));
                    fos.flush();
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

                signIndex ++;
                if (signIndex >= signList.size()) {
                    postDocumentURL = urlBase + "/index.htm";
                    documentURL = "";
                    sessionStatus.setComplete();
                }
                else {
                    documentURL = urlBase + DIR_DOCUMENTS + URIUtil.encodeQuery(signList.get (signIndex));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            try {
                postDocumentURL = urlBase + "/index.htm?error=" + URIUtil.encodeQuery(e.toString());
                documentURL = "";
            }
            catch (Exception x) {}
        }

        ModelAndView modelAndView = new ModelAndView("response");
        modelAndView.addObject(PARAM_POST_DOCUMENT_URL, postDocumentURL);
        modelAndView.addObject(PARAM_DOCUMENT_URL, documentURL);
        modelAndView.addObject(PARAM_TARGET, "_self");

        return modelAndView;
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }
}
