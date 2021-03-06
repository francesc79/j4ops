/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * PinDiaolog.java
 *
 * Created on Jan 27, 2012, 9:24:07 PM
 */
package it.j4ops.gui.dialog;

import java.awt.Dialog;
import java.awt.Window;

/**
 *
 * @author zanutto
 */
public class PinDiaolog extends javax.swing.JDialog {
    private String pin;
    
    /** Creates new form PinDiaolog */
    public PinDiaolog(Window owner, Dialog.ModalityType modalityType) {
        super(owner, modalityType);
        initComponents();
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jedtPin = new javax.swing.JPasswordField();
        jbutOk = new javax.swing.JButton();
        jbutCancel = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Get Pin");
        setResizable(false);

        jLabel1.setText("PIN:");

        jedtPin.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                jedtPinKeyReleased(evt);
            }
        });

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

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(51, 51, 51)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jedtPin, javax.swing.GroupLayout.PREFERRED_SIZE, 155, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(69, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(183, Short.MAX_VALUE)
                .addComponent(jbutOk, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jbutCancel)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(35, 35, 35)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jedtPin, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 42, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jbutCancel)
                    .addComponent(jbutOk))
                .addContainerGap())
        );

        jbutCancel.getAccessibleContext().setAccessibleName("jbutCancel");

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jbutCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutCancelActionPerformed
        pin = "";
        this.dispose();
    }//GEN-LAST:event_jbutCancelActionPerformed

    private void jbutOkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutOkActionPerformed
        

        if ((pin = new String (jedtPin.getPassword())) != null) {
            this.dispose();
        }
    }//GEN-LAST:event_jbutOkActionPerformed

    private void jedtPinKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_jedtPinKeyReleased
        if (evt.getKeyCode() == java.awt.event.KeyEvent.VK_ENTER) {
            if ((pin = new String (jedtPin.getPassword())) != null) {
                this.dispose();
            }        
        }
    }//GEN-LAST:event_jedtPinKeyReleased

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
            java.util.logging.Logger.getLogger(PinDiaolog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(PinDiaolog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(PinDiaolog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(PinDiaolog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {

            public void run() {
                PinDiaolog dialog = new PinDiaolog(new javax.swing.JFrame(), Dialog.ModalityType.APPLICATION_MODAL);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {

                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JButton jbutCancel;
    private javax.swing.JButton jbutOk;
    private javax.swing.JPasswordField jedtPin;
    // End of variables declaration//GEN-END:variables
}
