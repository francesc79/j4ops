package it.j4ops.web.controller;

import it.j4ops.web.model.UploadForm;
import it.j4ops.web.model.SignForm;
import it.j4ops.web.model.Document;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.ServletContextAware;

import javax.servlet.ServletContext;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

@Controller
public class HomeController implements ServletContextAware {

    private ServletContext servletContext;

    @ModelAttribute("uploadForm")
    public UploadForm getFileUploadForm () {
        return new UploadForm();
    }

    @ModelAttribute("signedDocumentList")
    public List<Document> getSignedDocumentList () {
        List<Document> signedDocumentList = new ArrayList<Document>();
        File dir = new File(servletContext.getRealPath("/signed"));
        if (dir != null) {
            for (File f : dir.listFiles()) {
                Document document = new Document ();
                document.setName(f.getName());
                document.setLastModified(new Date(f.lastModified()));
                document.setSize(f.length());
                signedDocumentList.add(document);
            }
        }
        return signedDocumentList;
    }

    @ModelAttribute("signForm")
    public SignForm getSignForm () {
        SignForm signForm = new SignForm ();
        File dir = new File(servletContext.getRealPath("/documents"));
        if (dir != null) {
            for (File f : dir.listFiles()) {
                Document document = new Document ();
                document.setName(f.getName());
                document.setLastModified(new Date(f.lastModified()));
                document.setSize(f.length());
                signForm.getDocumentList().add(document);
            }
        }

        signForm.setSignType("CAdES_BES");
        signForm.setAddSignInfo(false);
        return signForm;
    }

    @RequestMapping(value="/index.htm", method= RequestMethod.GET)
    public String getIndex(@ModelAttribute("error") String error) {
        return "index";
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }
}
