/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign.provider;

import it.j4ops.token.TokenInfo;
import java.util.List;

/**
 *
 * @author fzanutto
 */
public interface SignProviderHandler {
    public String getPassword () throws Exception;
    public TokenInfo selectToken(List<TokenInfo> lstTokenInfos)  throws Exception;
    public KeyIDAndX509Cert selectKeyIDAndX509Cert (List<KeyIDAndX509Cert> lstKeyAndX509Cert) throws Exception;
}
