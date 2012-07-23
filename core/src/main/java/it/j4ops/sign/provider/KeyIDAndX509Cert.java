/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign.provider;

import java.security.cert.X509Certificate;

/**
 *
 * @author fzanutto
 */
public class KeyIDAndX509Cert {
    private byte[] keyID;
    private X509Certificate x509Cert;
    private String certLabel;

    public byte[] getKeyID() {
        return keyID;
    }

    public void setKeyID(byte[] keyID) {
        this.keyID = keyID;
    }

    public X509Certificate getX509Cert() {
        return x509Cert;
    }

    public void setX509Cert(X509Certificate x509Cert) {
        this.x509Cert = x509Cert;
    }

    public String getCertLabel() {
        return certLabel;
    }

    public void setCertLabel(String certLabel) {
        this.certLabel = certLabel;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final KeyIDAndX509Cert other = (KeyIDAndX509Cert) obj;
        if (this.x509Cert != other.x509Cert && (this.x509Cert == null || !this.x509Cert.equals(other.x509Cert))) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 67 * hash + (this.x509Cert != null ? this.x509Cert.hashCode() : 0);
        return hash;
    }
}
