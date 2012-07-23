/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign;

import java.security.cert.X509Certificate;

/**
 *
 * @author fzanutto
 */
public interface Sign {
    public X509Certificate init () throws Exception;
    public void destroy () throws Exception;
}
