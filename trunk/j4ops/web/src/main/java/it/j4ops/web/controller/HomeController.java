package it.j4ops.web.controller;

import it.j4ops.web.model.Document;
import org.springframework.core.io.FileSystemResource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Controller
public class HomeController {

    @ModelAttribute
    public List<Document> getDocuments () {
        List<Document> listDocument = new ArrayList<Document>();
        FileSystemResource r = new FileSystemResource("documents/");
        for(File f : r.getFile().listFiles()) {
            Document document = new Document ();
            document.setFileName(f.getName());
            document.setLastModified(new Date(f.lastModified()));
            document.setSize(f.getTotalSpace());
            listDocument.add(document);
        }

        return listDocument;
    }

    @RequestMapping(value="/index.htm", method= RequestMethod.GET)
    public String getIndex() {
        return "index";
    }

    @RequestMapping(value="/sign.htm", method= RequestMethod.GET)
    public String getSign() {
        return "sign";
    }
}
