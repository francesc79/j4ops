package it.j4ops.web.controller;

import it.j4ops.verify.CmsVerify;
import it.j4ops.verify.PdfVerify;
import it.j4ops.verify.XmlVerify;
import it.j4ops.verify.bean.VerifyInfo;
import it.j4ops.web.model.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import static it.j4ops.web.config.WebMvcConfig.*;


@Controller
public class VerifyController implements ServletContextAware {

    private ServletContext servletContext;

    @Autowired
    private Configuration configuration;

    @RequestMapping(value = "/verify/{name:.+}", method = RequestMethod.GET)
    public ModelAndView verify (HttpServletRequest request, RedirectAttributes redirectAttributes, @PathVariable String name) throws Exception {
        ModelAndView modelAndView = new ModelAndView ("verify");
        VerifyInfo verifyInfo = null;
        FileInputStream fisEnvelope = null;
        FileInputStream fisData = null;
        FileOutputStream fos = null;

        try {
            String urlBase = request.getScheme () + "://" + request.getServerName () + ":" + request.getServerPort () + request.getContextPath ();
            String pathBase = servletContext.getRealPath("");
            String fileView = "";

            fisEnvelope = new FileInputStream (pathBase + DIR_DOCUMENTS + name);
            if (name.toLowerCase().endsWith(".p7m")) {
                File dir = new File (pathBase + DIR_VERIFIED);
                File tmp = File.createTempFile("verified", ".pdf", dir);
                fos = new FileOutputStream(tmp);
                CmsVerify cmsVerify = new CmsVerify (configuration.getProperties());
                verifyInfo = cmsVerify.verify(fisEnvelope, null, fos);
                fileView = DIR_VERIFIED + tmp.getName();
            }
            else if (name.toLowerCase().endsWith(".pdf")) {
                PdfVerify pdfVerify = new PdfVerify (configuration.getProperties());
                verifyInfo = pdfVerify.verify(fisEnvelope);
                fileView = name;
            }
            else if (name.toLowerCase().endsWith(".xml")) {
                XmlVerify xmlVerify = new XmlVerify (configuration.getProperties());
                verifyInfo = xmlVerify.verify(fisEnvelope);
                fileView = name;
            }
            else {
                redirectAttributes.addFlashAttribute("error", "file type not allowed");
                modelAndView.setViewName("redirect:index.htm");
            }

            if (verifyInfo != null) {
                modelAndView.addObject("verifyInfo", verifyInfo);
            }
            
            if (fileView != null) {
                modelAndView.addObject("fileView", urlBase + fileView);
            }
        }
        finally {
            try {
                if (fisEnvelope != null) {
                    fisEnvelope.close();
                }
            }
            catch (Exception ignored) {}

            try {
                if (fos != null) {
                    fos.close();
                }
            }
            catch (Exception ignored) {}            
        }

        return modelAndView;
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }
}
