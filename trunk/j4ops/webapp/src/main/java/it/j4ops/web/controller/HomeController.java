package it.j4ops.web.controller;

import it.j4ops.web.model.Configuration;
import it.j4ops.web.model.Document;
import it.j4ops.web.model.Sign;
import it.j4ops.web.model.Upload;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.ServletContextAware;

import javax.servlet.ServletContext;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static it.j4ops.web.config.WebMvcConfig.*;

@Controller
public class HomeController implements ServletContextAware {

    private ServletContext servletContext;

    @Autowired
    private Configuration config;

    @ModelAttribute("sign")
    public Sign getSign () {

        Sign sign = new Sign();
        File dir = new File(servletContext.getRealPath(DIR_DOCUMENTS));
        if (dir != null) {
            for (File f : dir.listFiles()) {
                Document document = new Document ();
                document.setName(f.getName());
                document.setLastModified(new Date(f.lastModified()));
                document.setSize(f.length());
                sign.getDocumentList().add(document);
            }
        }
        sign.setEnvelopeSignType(config.getEnvelopeSignType());
        sign.setSignMode(config.getSignMode());
        sign.setXmlSignMode(config.getXmlSignMode());
        sign.setAddSignInfo(false);
        return sign;
    }

    @RequestMapping(value="/index.htm", method= RequestMethod.GET)
    public String getIndex(@ModelAttribute("error") String error) {
        return "index";
    }

    @RequestMapping(value = "/delete/document/{name:.+}", method = RequestMethod.GET)
    public String deleteDocument (@PathVariable String name) {
        new File (servletContext.getRealPath(DIR_DOCUMENTS) + "/" + name).delete();
        return "index";
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }
}
