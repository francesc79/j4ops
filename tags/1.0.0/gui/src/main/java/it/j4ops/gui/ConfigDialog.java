/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * ConfigDialog.java
 *
 * Created on Jan 28, 2012, 3:48:38 PM
 */
package it.j4ops.gui;

import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import java.io.*;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 *
 * @author zanutto
 */
public class ConfigDialog extends javax.swing.JDialog {
    private static final String FileConfig = "j4ops.properties";
        
    public static final String FileConfigPKCS11Tokens = "PKCS11Tokens";
    public static final String FilePKCS12KeyStore = "PKCS12KeyStore";
    
    private Logger logger = Logger.getLogger(this.getClass());      
    private Properties properties = new Properties (getDefault());

    public Properties getProperties() {
        return (Properties)properties.clone();
    }    

    public String getProperty(String key) {
        return properties.getProperty(key);
    }
    
    private Properties getDefault () {
        Properties prop = new Properties ();
        prop.setProperty(FileConfigPKCS11Tokens, "tokens.xml");   
        prop.setProperty(FilePKCS12KeyStore, "j4ops.p12");
        
        prop.setProperty(SecurityProvider.getLiteral(), "BC");             
        prop.setProperty(DigestAlgName.getLiteral(), "SHA256");
        prop.setProperty(EncryptionAlgName.getLiteral(), "RSA");
        prop.setProperty(EnvelopeEncode.getLiteral(), "DER");        
        prop.setProperty(EnvelopeSignType.getLiteral(), SignType.PAdES_BES.getLiteral());        
        prop.setProperty(TSAURL.getLiteral(), "http://timestamping.edelweb.fr/service/tsp"); 
        prop.setProperty(TSAUser.getLiteral(), ""); 
        prop.setProperty(TSAPassword.getLiteral(), ""); 
        prop.setProperty(VerifyCRL.getLiteral(), "false");
        prop.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), "certs.ks");         
        prop.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), "j4ops");         

        return prop;
    }
    
    /** Creates new form ConfigDialog */
    public ConfigDialog(java.awt.Frame parent, boolean modal) throws Exception {
        super(parent, modal);
        initComponents();
        
        InputStream is = null;
        try {
            if (new File (FileConfig).exists() == true) {
                is = new FileInputStream(FileConfig);
            }
            else {
                is = getClass().getClassLoader().getResourceAsStream (FileConfig);
            }
            properties.load(is);
        }
        catch (FileNotFoundException ex) {
            logger.fatal(ex.getMessage(), ex);
        }
        finally {
            try {
                if (is != null) {
                    is.close();
                    is = null;
                }
            }
            catch (Exception ex) {}
        }
        jedtPKCS11Tokens.setText(properties.getProperty(FileConfigPKCS11Tokens));
        jedtPKCS12KeyStore.setText(properties.getProperty(FilePKCS12KeyStore));        
        jedtTSAURL.setText(properties.getProperty(TSAURL.getLiteral()));
        jedtTSAUser.setText(properties.getProperty(TSAUser.getLiteral()));
        jedtTSAPassword.setText(properties.getProperty(TSAPassword.getLiteral()));

        jedtFileKeyStoreTrustedRootCerts.setText(properties.getProperty(FileKeyStoreTrustedRootCerts.getLiteral()));
        jedtPassKeyStoreTrustedRootCerts.setText(properties.getProperty(PassKeyStoreTrustedRootCerts.getLiteral()));                
        jcmbVerifyCRL.setSelectedItem(properties.getProperty(VerifyCRL.getLiteral()));        
        jcmbDigestAlgName.setSelectedItem(properties.getProperty(DigestAlgName.getLiteral()));    
        jcmbEncryptionAlgName.setSelectedItem(properties.getProperty(EncryptionAlgName.getLiteral()));
        jcmbEnvelopeEncode.setSelectedItem(properties.getProperty(EnvelopeEncode.getLiteral()));        
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jbutOk = new javax.swing.JButton();
        jbutCancel = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jedtPKCS12KeyStore = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jedtPKCS11Tokens = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jedtTSAURL = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        jedtTSAUser = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        jedtTSAPassword = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jcmbDigestAlgName = new javax.swing.JComboBox();
        jcmbEncryptionAlgName = new javax.swing.JComboBox();
        jLabel7 = new javax.swing.JLabel();
        jcmbEnvelopeEncode = new javax.swing.JComboBox();
        jLabel8 = new javax.swing.JLabel();
        jcmbVerifyCRL = new javax.swing.JComboBox();
        jLabel10 = new javax.swing.JLabel();
        jLabel11 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        jedtFileKeyStoreTrustedRootCerts = new javax.swing.JTextField();
        jedtPassKeyStoreTrustedRootCerts = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Config");

        jbutOk.setText("OK");
        jbutOk.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutOkActionPerformed(evt);
            }
        });

        jbutCancel.setText("Cancel");
        jbutCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutCancelActionPerformed(evt);
            }
        });

        jLabel1.setText("PKCS12 KeyStore:");

        jLabel2.setText("PKCS11 Tokens:");

        jLabel3.setText("TSA URL:");

        jLabel4.setText("TSA User:");

        jLabel5.setText("TSA Password:");

        jLabel6.setText("DigestAlgName:");

        jcmbDigestAlgName.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "SHA1", "SHA256", "SHA384", "SHA512" }));

        jcmbEncryptionAlgName.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "RSA", "DSA" }));

        jLabel7.setText("EncryptionAlgName:");

        jcmbEnvelopeEncode.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "DER", "B64" }));

        jLabel8.setText("EnvelopeEncode:");

        jcmbVerifyCRL.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "true", "false" }));

        jLabel10.setText("VerifyCRL:");

        jLabel11.setText("FileKeyStoreTrustedRootCerts:");

        jLabel12.setText("PassKeyStoreTrustedRootCerts:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel11, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel4, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel5, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel6, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel7, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel12, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel3, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel8, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel10, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jcmbDigestAlgName, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGap(278, 278, 278))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jcmbEncryptionAlgName, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGap(278, 278, 278))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jcmbEnvelopeEncode, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGap(278, 278, 278))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jcmbVerifyCRL, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGap(278, 278, 278))
                            .addComponent(jedtPKCS11Tokens, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jedtPKCS12KeyStore)
                            .addComponent(jedtFileKeyStoreTrustedRootCerts)
                            .addComponent(jedtTSAURL)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jedtTSAPassword)
                                    .addComponent(jedtTSAUser)
                                    .addComponent(jedtPassKeyStoreTrustedRootCerts))
                                .addGap(171, 171, 171))))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(544, 544, 544)
                        .addComponent(jbutOk, javax.swing.GroupLayout.PREFERRED_SIZE, 63, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jbutCancel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtPKCS12KeyStore)
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtPKCS11Tokens, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtFileKeyStoreTrustedRootCerts, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel11))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtPassKeyStoreTrustedRootCerts, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel12))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtTSAURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtTSAUser, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtTSAPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jcmbDigestAlgName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel6))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jcmbEncryptionAlgName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jcmbEnvelopeEncode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel8))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel10)
                    .addComponent(jcmbVerifyCRL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(17, 17, 17)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jbutOk, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jbutCancel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jbutOkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutOkActionPerformed

        // save config
        try {
            FileOutputStream fos = null;
            try {
                properties.setProperty(FileConfigPKCS11Tokens, jedtPKCS11Tokens.getText());
                properties.setProperty(FilePKCS12KeyStore, jedtPKCS12KeyStore.getText());
                properties.setProperty(TSAURL.getLiteral(), jedtTSAURL.getText());
                properties.setProperty(TSAUser.getLiteral(), jedtTSAUser.getText());
                properties.setProperty(TSAPassword.getLiteral(), jedtTSAPassword.getText());

                properties.setProperty(FileKeyStoreTrustedRootCerts.getLiteral(), jedtFileKeyStoreTrustedRootCerts.getText());
                properties.setProperty(PassKeyStoreTrustedRootCerts.getLiteral(), jedtPassKeyStoreTrustedRootCerts.getText());                
                properties.setProperty(VerifyCRL.getLiteral(), (String)jcmbVerifyCRL.getSelectedItem());
                properties.setProperty(DigestAlgName.getLiteral(), (String)jcmbDigestAlgName.getSelectedItem());                
                properties.setProperty(EncryptionAlgName.getLiteral(), (String)jcmbEncryptionAlgName.getSelectedItem());                 
                properties.setProperty(EnvelopeEncode.getLiteral(), (String)jcmbEnvelopeEncode.getSelectedItem());                 

                fos = new FileOutputStream(FileConfig);
                properties.store(fos, "");
            }
            finally {
                try {
                    if (fos != null) {
                        fos.close();
                        fos = null;
                    }
                }
                catch (Exception ex) {}
            }    
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
        }
        
        dispose();
    }//GEN-LAST:event_jbutOkActionPerformed

    private void jbutCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutCancelActionPerformed
        dispose();
    }//GEN-LAST:event_jbutCancelActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ConfigDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ConfigDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ConfigDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ConfigDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {

            public void run() {
                try {
                    ConfigDialog dialog = new ConfigDialog(new javax.swing.JFrame(), true);
                    dialog.addWindowListener(new java.awt.event.WindowAdapter() {

                        @Override
                        public void windowClosing(java.awt.event.WindowEvent e) {
                            System.exit(0);
                        }
                    });
                    dialog.setVisible(true);
                }
                catch (Exception ex) {
                    ex.printStackTrace();
                }                    
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JButton jbutCancel;
    private javax.swing.JButton jbutOk;
    private javax.swing.JComboBox jcmbDigestAlgName;
    private javax.swing.JComboBox jcmbEncryptionAlgName;
    private javax.swing.JComboBox jcmbEnvelopeEncode;
    private javax.swing.JComboBox jcmbVerifyCRL;
    private javax.swing.JTextField jedtFileKeyStoreTrustedRootCerts;
    private javax.swing.JTextField jedtPKCS11Tokens;
    private javax.swing.JTextField jedtPKCS12KeyStore;
    private javax.swing.JTextField jedtPassKeyStoreTrustedRootCerts;
    private javax.swing.JTextField jedtTSAPassword;
    private javax.swing.JTextField jedtTSAURL;
    private javax.swing.JTextField jedtTSAUser;
    // End of variables declaration//GEN-END:variables
}
