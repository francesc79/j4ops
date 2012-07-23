/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops;

/**
 *
 * @author fzanutto
 */
public enum PropertyConstants {
    DigestAlgName("DigestAlgName"),
    EnvelopeSignType("EnvelopeSignType"),
    EnvelopeEncode("EnvelopeEncode"),
    EncryptionAlgName("EncryptionAlgName"),
    TSAURL("TSAURL"),
    TSAUser("TSAUser"),    
    TSAPassword("TSAPassword"), 
    SecurityProvider("SecurityProvider"), 
    VerifyCRL("VerifyCRL"),
    VerifyCertificate("VerifyCertificate"),    
    FileKeyStoreTrustedRootCerts("FileKeyStoreTrustedRootCerts"),
    PassKeyStoreTrustedRootCerts("PassKeyStoreTrustedRootCerts");  
    
    private String literal;
    private PropertyConstants (String literal) {
        this.literal = literal;
    }

    public String getLiteral() {
        return literal;
    } 
}
