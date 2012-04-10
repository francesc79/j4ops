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
public interface SignProvider {
    public void init (String digestAlgName, String encryptionAlgName, SignProviderHandler handlerProvider, String securityProvider) throws Exception;
    public void destroy () throws Exception;
    public byte [] sign(byte[] toEncrypt) throws Exception;
    public X509Certificate getX509Certificate ();
    public String getCertLabel ();    
}
