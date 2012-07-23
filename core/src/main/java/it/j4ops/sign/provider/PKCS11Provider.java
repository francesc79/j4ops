/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign.provider;

import it.j4ops.token.TokenInfo;
import it.j4ops.token.TokenReader;
import java.util.List;

/**
 *
 * @author fzanutto
 */
public abstract class PKCS11Provider implements SignProvider {
    private TokenInfo tokenInfo;
    private String tokensConfig;
        
    public PKCS11Provider (String tokensConfig) {
        this.tokensConfig = tokensConfig;
    }
    
    public void setTokensConfig (String tokensConfig) {
        this.tokensConfig = tokensConfig;
    }
    
    
    @Override
    public void init (String digestAlgName, String encryptionAlgName, SignProviderHandler handlerProvider, String securityProvider) throws Exception {
        List<TokenInfo> lstTokens = TokenReader.listTokens (tokensConfig);
        if (lstTokens.isEmpty()) {
            throw new Exception ("No token found");
        }
        tokenInfo = handlerProvider.selectToken(lstTokens);
        if (tokenInfo == null) {
            throw new Exception ("Token not selected");
        }
    }

    public TokenInfo getTokenInfo() {
        return tokenInfo;
    }
}
