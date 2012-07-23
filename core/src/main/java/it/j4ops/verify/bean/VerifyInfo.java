/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.verify.bean;


import java.util.ArrayList;

/**
 *
 * @author fzanutto
 */
public class VerifyInfo {
    private ArrayList<SignerInfo> lstSignerInfos = new ArrayList<SignerInfo>();
    private int countSigns = 0;    

    public ArrayList<SignerInfo> getSignerInfos () {
        return lstSignerInfos;
    }
    
    public void addSignerInfo (SignerInfo signerInfo) {
        lstSignerInfos.add(signerInfo);
        countSigns ++;
    }

    public int getCountSigns() {
        return countSigns;
    }
}
