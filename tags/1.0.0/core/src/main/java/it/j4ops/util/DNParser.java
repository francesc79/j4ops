/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.util;

import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author fzanutto
 */
public class DNParser {
    
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
}
