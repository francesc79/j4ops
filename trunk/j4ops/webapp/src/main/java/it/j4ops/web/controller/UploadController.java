package it.j4ops.web.controller;

import it.j4ops.util.DERUtil;
import it.j4ops.web.model.Upload;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.ServletContext;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.List;

import static it.j4ops.web.config.WebMvcConfig.*;

@Controller
public class UploadController implements ServletContextAware {

    private ServletContext servletContext;

    @ModelAttribute("upload")
    public Upload getUpload () {
        return new Upload();
    }

    @RequestMapping(value = "/upload/document.htm", method = RequestMethod.GET)
    public String uploadDocument(Model model) throws Exception {
        model.addAttribute("path", "/upload/document.htm");
        return "upload";
    }

    @RequestMapping(value = "/upload/document.htm", method = RequestMethod.POST)
    public String uploadDocument(Upload upload, BindingResult result, Model model) throws Exception {

        List<MultipartFile> files = upload.getFiles();
        String pathBase = servletContext.getRealPath("");

        if (!result.hasErrors()) {
            if (files != null && files.size() > 0) {
                for (MultipartFile multipartFile : files) {

                    FileOutputStream fos = null;
                    InputStream is = null;
                    try {
                        is =  multipartFile.getInputStream();
                        fos = new FileOutputStream (pathBase + DIR_DOCUMENTS + multipartFile.getOriginalFilename());
                        fos.write(DERUtil.streamToByteArray(is));
                    }
                    finally {
                        try {
                            if (fos != null) {
                                fos.close();
                            }

                        }
                        catch (Exception ex) {}

                        try {
                            if (is != null) {
                                is.close();
                            }

                        }
                        catch (Exception ex) {}
                    }
                }
            }
            model.addAttribute("close", true);
        }

        return "upload";
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }
}
