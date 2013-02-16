package it.j4ops.web.model;


import it.j4ops.web.model.Document;

import java.util.ArrayList;
import java.util.List;

public class Sign {
    private List<Document> documentList;
    private String envelopeSignType;
    private String signMode;
    private String xmlSignMode;
    private boolean addSignInfo;
    private String action;

    public List<Document> getDocumentList() {
        if (documentList == null) {
            documentList = new ArrayList<Document>();
        }
        return documentList;
    }

    public void setDocumentList(List<Document> documentList) {
        this.documentList = documentList;
    }

    public String getEnvelopeSignType() {
        return envelopeSignType;
    }

    public void setEnvelopeSignType(String envelopeSignType) {
        this.envelopeSignType = envelopeSignType;
    }

    public boolean isAddSignInfo() {
        return addSignInfo;
    }

    public void setAddSignInfo(boolean addSignInfo) {
        this.addSignInfo = addSignInfo;
    }

    public String getSignMode() {
        return signMode;
    }

    public void setSignMode(String signMode) {
        this.signMode = signMode;
    }

    public String getXmlSignMode() {
        return xmlSignMode;
    }

    public void setXmlSignMode(String xmlSignMode) {
        this.xmlSignMode = xmlSignMode;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }
}
