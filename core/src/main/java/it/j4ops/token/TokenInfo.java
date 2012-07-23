/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.token;

/**
 *
 * @author fzanutto
 */
public class TokenInfo {
    private String atr;
    private int slotID;
    private String terminalName;
    private String driver;
    private String driverDescription;
    private boolean tokenPresent;
    
    public String getAtr() {
        return atr;
    }

    public void setAtr(String atr) {
        this.atr = atr;
    }

    public int getSlotID() {
        return slotID;
    }

    public void setSlotID(int slotID) {
        this.slotID = slotID;
    }

    public String getTerminalName() {
        return terminalName;
    }

    public void setTerminalName(String terminalName) {
        this.terminalName = terminalName;
    }

    public String getDriver() {
        return driver;
    }

    public void setDriver(String driver) {
        this.driver = driver;
    }

    public String getDriverDescription() {
        return driverDescription;
    }

    public void setDriverDescription(String driverDescription) {
        this.driverDescription = driverDescription;
    }

    public boolean isTokenPresent() {
        return tokenPresent;
    }

    public void setTokenPresent(boolean tokenPresent) {
        this.tokenPresent = tokenPresent;
    }

    @Override
    public String toString() {
        return terminalName;
    }
}
