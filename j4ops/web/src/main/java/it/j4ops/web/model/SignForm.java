package it.j4ops.web.model;


import it.j4ops.web.model.Document;

import java.util.ArrayList;
import java.util.List;

public class SignForm {
    private List<Document> documentList;
    private String signType;
    private boolean addSignInfo;

    public List<Document> getDocumentList() {
        if (documentList == null) {
            documentList = new ArrayList<Document>();
        }
        return documentList;
    }

    public void setDocumentList(List<Document> documentList) {
        this.documentList = documentList;
    }

    public String getSignType() {
        return signType;
    }

    public void setSignType(String signType) {
        this.signType = signType;
    }

    public boolean isAddSignInfo() {
        return addSignInfo;
    }

    public void setAddSignInfo(boolean addSignInfo) {
        this.addSignInfo = addSignInfo;
    }
}
