/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 *
 * @author fzanutto
 */
public class DNParser {
    /*
    private BCStrictStyle bcStyle = new BCStrictStyle(); 
    private X500Name name = null;
    
    public DNParser (String dn) {
        name = new X500Name(dn);
    }
    
    public String getValue (String id) {
        RDN []rdns = name.getRDNs(bcStyle.attrNameToOID(id));
        if (rdns != null && rdns.length > 0) {
            if (rdns[0].isMultiValued() == false) {
                return IETFUtils.valueToString(rdns[0].getFirst().getValue());
            }
        }        
        return null;
    }
    
    public List<String> getValues (String id) {
        ArrayList<String> lstVals = new ArrayList<String>();
        RDN []rdns = name.getRDNs(bcStyle.attrNameToOID(id));
        if (rdns != null && rdns.length > 0) {
            if (rdns[0].isMultiValued() == true) {
                for (AttributeTypeAndValue attr : rdns[0].getTypesAndValues()) {
                    lstVals.add(IETFUtils.valueToString(attr));
                }
            }
        }        
        return null;
    }    
    
    public static String parse(String dn, String id) {
        X500Name name = new X500Name(dn);
        BCStrictStyle style = new BCStrictStyle();
        RDN []rdns = name.getRDNs(style.attrNameToOID(id));
        if (rdns != null && rdns.length > 0) {
            if (rdns[0].isMultiValued() == false) {
                return IETFUtils.valueToString(rdns[0].getFirst().getValue());
            }
        }        
        return null;      
    }
     * 
     */
    
    
    private static final String REGEX_DN = "([A-Za-z ]*)=([A-Za-z0-9: /]*)[,]?";
    private HashMap<String, String> values = new HashMap<String, String>();
    
    public DNParser (String dn) {
        Matcher m = Pattern.compile(REGEX_DN).matcher(dn);
        while (m.find()) {
            values.put(m.group(1).trim(), m.group(2));
        }
    }
    
    public String get (String key) {
        return values.get(key);
    }
    
    public static String parse(String dn, String id) {
        DNParser parser = new DNParser(dn);
        return parser.get(id);
    }
    
    public static void main (String[]args) throws Exception {
    
        
        String dn = "CN=Francesco Zanutto, DNQ=201014947433, SERIALNUMBER=IT:ZNTFNC79B25H816E, GIVENNAME=FRANCESCO, SURNAME=ZANUTTO, O=NON PRESENTE, C=IT";
 
        System.out.println ("DNParser:" + DNParser.parse(dn, "SERIALNUMBER"));
        
        
        Matcher m = Pattern.compile("([A-Za-z ]*)=([A-Za-z0-9: ]*)[,]?").matcher(dn);
        while (m.find()) {
          //System.out.println (" " + m.group());   
          //System.out.println ("g1:" + m.group(0));  
          System.out.println ("g2:" + m.group(1));
          System.out.println ("g3:" + m.group(2));          
        }
    }
}
