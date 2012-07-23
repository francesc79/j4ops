/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.verify.bean;

import it.j4ops.SignType;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import org.bouncycastle.cms.SignerInformation;

/**
 *
 * @author fzanutto
 */
public class SignerInfo {
    private boolean counterSignature;
    private Date dateSign;
    private String author;
    private X509Certificate x509Cert;
    private SignerInformation signerInformation;
    private SignType signType;
    private int level;

    private ArrayList<SignerInfo> lstSignerInfos = new ArrayList<SignerInfo>();

    public ArrayList<SignerInfo> getSignerInfos () {
        return lstSignerInfos;
    }
    
    public void addSignerInfo (SignerInfo signerInfo) {
        lstSignerInfos.add(signerInfo);
    }    
    
    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public boolean isCounterSignature() {
        return counterSignature;
    }

    public void setCounterSignature(boolean counterSignature) {
        this.counterSignature = counterSignature;
    }

    public Date getDateSign() {
        return dateSign;
    }

    public void setDateSign(Date dateSign) {
        this.dateSign = dateSign;
    }

    public SignerInformation getSignerInformation() {
        return signerInformation;
    }

    public void setSignerInformation(SignerInformation signerInformation) {
        this.signerInformation = signerInformation;
    }

    public X509Certificate getX509Cert() {
        return x509Cert;
    }

    public void setX509Cert(X509Certificate x509Cert) {
        this.x509Cert = x509Cert;
    }

    public SignType getSignType() {
        return signType;
    }

    public void setSignType(SignType signType) {
        this.signType = signType;
    }

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    @Override
    public String toString() {
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy hh:mm:ss");
        return String.format("%d SignerInfo Author:%s DateSign:%s SignType %s", level, author, sdf.format(dateSign), signType);
    }
}
