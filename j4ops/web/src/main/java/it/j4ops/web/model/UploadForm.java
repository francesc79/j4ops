package it.j4ops.web.model;


import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

public class UploadForm {
    private List<MultipartFile> files;

    public List<MultipartFile> getFiles() {
        if (files == null) {
            files = new ArrayList<MultipartFile>();
        }
        return files;
    }

    public void setFiles(List<MultipartFile> files) {
        this.files = files;
    }
}
