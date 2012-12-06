package it.j4ops.web.controller;

import it.j4ops.web.model.UploadForm;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Set;

@Controller
public class UploadController {

    @RequestMapping(value = "/uploadDocument.htm", method = RequestMethod.POST)
    public String uploadDocument(UploadForm uploadForm, BindingResult result) {

        List<MultipartFile> files = uploadForm.getFiles();

System.out.println("files:" + files);

        if (files != null && files.size() > 0) {
            for (MultipartFile multipartFile : files) {
               System.out.println("getOriginalFilename:" + multipartFile.getOriginalFilename());
                //Handle file content - multipartFile.getInputStream()
            }
        }


        return "redirect:index.htm";
    }
}
