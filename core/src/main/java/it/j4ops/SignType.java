/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops;

/**
 *
 * @author fzanutto
 */
public enum SignType {
    Pkcs7("Pkcs7"),
    CAdES_BES("CAdES_BES"),
    CAdES_T("CAdES_T"),
    CAdES_A("CAdES_A"),
    CAdES_C("CAdES_C"),
    CAdES_EPES("CAdES_EPES"),
    CAdES_X_1("CAdES_X_1"),
    CAdES_X_2("CAdES_X_2"),
    CAdES_X_L("CAdES_X_L"),
    
    PDF("PDF"),    
    PAdES_BES("PAdES_BES"),     
    PAdES_T("PAdES_T"),  
    PAdES_A("PAdES_A"), 
    PAdES_C("PAdES_C"),     
    PAdES_EPES("PAdES_EPES"), 
    PAdES_X_1("PAdES_X_1"),     
    PAdES_X_2("PAdES_X_2"),
    PAdES_X_L("PAdES_X_L"),
        
    XMLDSIG("XMLDSIG"),
    XAdES_BES("XAdES_BES"),
    XAdES_T("XAdES_T"),
    XAdES_C("XAdES_C"),
    XAdES_X_1("XAdES_X_1"),
    XAdES_X_2("XAdES_X_2"),
    XAdES_X_L("XAdES_X_L"),
    XAdES_A("XAdES_A");   
    
    
    private final String literal;    
    private SignType(String literal) {
        this.literal = literal;
    }
    
    public String getLiteral() {
        return literal;
    }
}
