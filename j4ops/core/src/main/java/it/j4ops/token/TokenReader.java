/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.token;

import it.j4ops.util.HexString;
import java.util.ArrayList;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author fzanutto
 */
public class TokenReader {
    private static Logger logger = LoggerFactory.getLogger(TokenReader.class);
    
    public static List<TokenInfo> listTokens (String file) throws Exception {
        ArrayList<TokenInfo> lstTokenInfos = new ArrayList<TokenInfo>();
        List<CardTerminal> lstTerminals= null;
        Card card = null;     
        
        TerminalFactory factory = TerminalFactory.getDefault();
        lstTerminals = factory.terminals().list();
        
        if (lstTerminals.isEmpty()) {
            throw new Exception ("No terminal detected");
        }
        else {
            for (int index = 0; index < lstTerminals.size(); index ++) {
                CardTerminal ct = lstTerminals.get(index);
                logger.debug(String.format("Terminal:%s check card", ct.getName()));
                
                if (ct.isCardPresent()) {
                    card = ct.connect("*");
                    
                    logger.debug(String.format("SlotId: %d Terminal: %s ATR: %s", index, ct.getName(), 
                        HexString.hexify(card.getATR().getBytes())));                    

                    TokenInfo tokenInfo = new TokenInfo();
                    tokenInfo.setAtr(HexString.hexify(card.getATR().getBytes()));
                    tokenInfo.setSlotID(index);
                    tokenInfo.setTerminalName(ct.getName());
                    
                    // recognize card
                    if (TokenRecognize.recognize(file, tokenInfo) != null) {
                        lstTokenInfos.add (tokenInfo);
                    }

                    card.disconnect(true);
                }   
            }

        }    
        return lstTokenInfos;        
    }
    
    public static void main (String []args) throws Exception {
        listTokens("tokens.xml");
    }
}
