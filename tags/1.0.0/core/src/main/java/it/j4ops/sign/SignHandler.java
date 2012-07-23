/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.sign;

import it.j4ops.sign.provider.SignProviderHandler;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

/**
 *
 * @author fzanutto
 */
public interface SignHandler extends SignProviderHandler {
    public SignerInformation selectSigner (Store certs, SignerInformationStore signers)  throws Exception;
}
