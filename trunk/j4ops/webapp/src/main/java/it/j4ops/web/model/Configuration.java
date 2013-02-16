package it.j4ops.web.model;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.util.Properties;

@Component
public class Configuration {

    @Value("${PKCS12KeyStore}")
    private String PKCS12KeyStore;

    @Value("${VerifyCertificate}")
    private String verifyCertificate;

    @Value("${SecurityProvider}")
    private String securityProvider;

    @Value("${PassKeyStoreTrustedRootCerts}")
    private String passKeyStoreTrustedRootCerts;

    @Value("${FileKeyStoreTrustedRootCerts}")
    private String fileKeyStoreTrustedRootCerts;

    @Value("${EnvelopeEncode}")
    private String envelopeEncode;

    @Value("${VerifyCRL}")
    private String verifyCRL;

    @Value("${PKCS11Tokens}")
    private String PKCS11Tokens;

    @Value("${DigestAlgName}")
    private String digestAlgName;

    @Value("${EnvelopeSignType}")
    private String envelopeSignType;

    @Value("${EncryptionAlgName}")
    private String encryptionAlgName;

    @Value("${SignMode}")
    private String signMode;

    @Value("${XmlSignMode}")
    private String xmlSignMode;

    @Value("${TSAURL}")
    private String TSAURL;

    @Value("${TSAUser}")
    private String TSAUser;

    @Value("${TSAPassword}")
    private String TSAPassword;

    public Configuration() {
    }

    public String getPKCS12KeyStore() {
        return PKCS12KeyStore;
    }

    public void setPKCS12KeyStore(String PKCS12KeyStore) {
        this.PKCS12KeyStore = PKCS12KeyStore;
    }

    public String getVerifyCertificate() {
        return verifyCertificate;
    }

    public void setVerifyCertificate(String verifyCertificate) {
        this.verifyCertificate = verifyCertificate;
    }

    public String getSecurityProvider() {
        return securityProvider;
    }

    public void setSecurityProvider(String securityProvider) {
        this.securityProvider = securityProvider;
    }

    public String getPassKeyStoreTrustedRootCerts() {
        return passKeyStoreTrustedRootCerts;
    }

    public void setPassKeyStoreTrustedRootCerts(String passKeyStoreTrustedRootCerts) {
        this.passKeyStoreTrustedRootCerts = passKeyStoreTrustedRootCerts;
    }

    public String getEnvelopeEncode() {
        return envelopeEncode;
    }

    public void setEnvelopeEncode(String envelopeEncode) {
        this.envelopeEncode = envelopeEncode;
    }

    public String getVerifyCRL() {
        return verifyCRL;
    }

    public void setVerifyCRL(String verifyCRL) {
        this.verifyCRL = verifyCRL;
    }

    public String getPKCS11Tokens() {
        return PKCS11Tokens;
    }

    public void setPKCS11Tokens(String PKCS11Tokens) {
        this.PKCS11Tokens = PKCS11Tokens;
    }

    public String getFileKeyStoreTrustedRootCerts() {
        return fileKeyStoreTrustedRootCerts;
    }

    public void setFileKeyStoreTrustedRootCerts(String fileKeyStoreTrustedRootCerts) {
        this.fileKeyStoreTrustedRootCerts = fileKeyStoreTrustedRootCerts;
    }

    public String getDigestAlgName() {
        return digestAlgName;
    }

    public void setDigestAlgName(String digestAlgName) {
        this.digestAlgName = digestAlgName;
    }

    public String getEnvelopeSignType() {
        return envelopeSignType;
    }

    public void setEnvelopeSignType(String envelopeSignType) {
        this.envelopeSignType = envelopeSignType;
    }

    public String getEncryptionAlgName() {
        return encryptionAlgName;
    }

    public void setEncryptionAlgName(String encryptionAlgName) {
        this.encryptionAlgName = encryptionAlgName;
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

    public String getTSAURL() {
        return TSAURL;
    }

    public void setTSAURL(String TSAURL) {
        this.TSAURL = TSAURL;
    }

    public String getTSAUser() {
        return TSAUser;
    }

    public void setTSAUser(String TSAUser) {
        this.TSAUser = TSAUser;
    }

    public String getTSAPassword() {
        return TSAPassword;
    }

    public void setTSAPassword(String TSAPassword) {
        this.TSAPassword = TSAPassword;
    }

    public Properties getProperties() throws Exception {
        Properties prop = new Properties();
        Field[] fields = this.getClass().getDeclaredFields();
        for (Field field : fields) {
            field = this.getClass().getDeclaredField (field.getName());
            field.setAccessible(true);
            Value value = field.getAnnotation(Value.class);
            String key = value.value();
            if (key.startsWith("${") && key.endsWith("}")) {
                key = key.substring(2, key.length() - 1);
            }
            Object obj = field.get(this);
            prop.setProperty(key, (obj!=null)?obj.toString():"");
        }
        return prop;
    }

    public void updateProperties (Properties prop) throws Exception {
        Field[] fields = this.getClass().getDeclaredFields();
        for (Field field : fields) {
            field = this.getClass().getDeclaredField (field.getName());
            field.setAccessible(true);
            Value value = field.getAnnotation(Value.class);
            String key = value.value();
            if (key.startsWith("${") && key.endsWith("}")) {
                key = key.substring(2, key.length() - 1);
            }

            String val = prop.getProperty(key);
            if (val != null && !"".equals(val)) {
                field.set(this, val);
            }
        }
    }
}
