/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * J4OPSMainForm.java
 *
 * Created on Jan 27, 2012, 8:42:15 PM
 */
package it.j4ops.gui;

import it.j4ops.CmsSignMode;
import static it.j4ops.PropertyConstants.*;
import it.j4ops.SignType;
import it.j4ops.XmlSignMode;
import it.j4ops.sign.CmsSign;
import it.j4ops.sign.PdfSign;
import it.j4ops.sign.XmlSign;
import it.j4ops.sign.provider.*;
import it.j4ops.token.TokenInfo;
import it.j4ops.util.DNParser;
import it.j4ops.util.X509Util;
import it.j4ops.verify.CmsVerify;
import it.j4ops.verify.PdfVerify;
import it.j4ops.verify.XmlVerify;
import it.j4ops.verify.bean.SignerInfo;
import it.j4ops.verify.bean.VerifyInfo;
import java.io.*;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;

/**
 *
 * @author zanutto
 */
public class J4OPSMainForm extends javax.swing.JFrame {
    private static Logger logger = Logger.getLogger(J4OPSMainForm.class);     
    private CertificateTableModel trustCertsTableModel = new CertificateTableModel();    
    private DefaultComboBoxModel modelSignProviders = new DefaultComboBoxModel();
    private DefaultComboBoxModel modelSignTypes = new DefaultComboBoxModel(); 
    private GuiSignHandler signHandler = new GuiSignHandler(this);
    private ConfigDialog configDialog = new ConfigDialog (this,true);
    private TokenInfoTableModel tableModelTokens = new TokenInfoTableModel ();
    private VerifyTableModel tableModelVerify = new VerifyTableModel ();
    
    public static final int TAB_SIGN = 0;
    public static final int TAB_MULTI_SIGN = 1;
    public static final int TAB_VERIFY = 2;
    public static final int TAB_TRUST_CERTS = 3;
    public static final int TAB_TOKENS = 4;

    
    public J4OPSMainForm() throws Exception {
        
        // add sign type
        modelSignTypes.addElement(SignType.Pkcs7);
        modelSignTypes.addElement(SignType.CAdES_BES);        
        modelSignTypes.addElement(SignType.CAdES_T);
        modelSignTypes.addElement(SignType.PDF);
        modelSignTypes.addElement(SignType.PAdES_BES);        
        modelSignTypes.addElement(SignType.PAdES_T);
        modelSignTypes.addElement(SignType.XMLDSIG);
        modelSignTypes.addElement(SignType.XAdES_BES);
        modelSignTypes.addElement(SignType.XAdES_T);         
        
        // init components
        initComponents();

        // add sign providers
        modelSignProviders.addElement(new PKCS12Provider (""));
        SunPKCS11Provider sunPKCS11Provider = new SunPKCS11Provider ("");
        modelSignProviders.addElement(sunPKCS11Provider);
        modelSignProviders.addElement(new IaikPKCS11Provider ("")); 
        jcmbSignProvider.setSelectedItem(sunPKCS11Provider);        
        
        // set default sign type
        jcmbSignType.setSelectedItem(SignType.CAdES_BES);
        
        // load trusted certs
        TableColumn column = jtabTrustedCerts.getColumn("GetCert");
        ImageIcon icon = new ImageIcon(getClass().getClassLoader().getResource("images/certificate.gif"));
        column.setWidth(icon.getIconWidth());
        column.setPreferredWidth(icon.getIconWidth());
        jtabTrustedCerts.setRowHeight(icon.getIconHeight() + 5);
        reloadTrustCerts ();
        
        // set size row
        column = jtabVerifyInfo.getColumn("GetCert");
        column.setWidth(icon.getIconWidth());
        column.setPreferredWidth(icon.getIconWidth());
        jtabVerifyInfo.setRowHeight(icon.getIconHeight() + 5);        
    }
    
    private void reloadTrustCerts () throws Exception {
        trustCertsTableModel.removeAll();
        Properties prop = configDialog.getProperties();        
        Set<X509Certificate> trustedCerts =  X509Util.loadKeyStore(prop.getProperty(FileKeyStoreTrustedRootCerts.getLiteral()),
                                                                   prop.getProperty(PassKeyStoreTrustedRootCerts.getLiteral()));            
        Iterator<X509Certificate> iter = trustedCerts.iterator();
        while (iter.hasNext()) {
            trustCertsTableModel.addX509Certificate(iter.next());
        }    
    }
    
    private void refreshTokens () {
        logger.info("refreshTokens");
        tableModelTokens.removeAll();  
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> lstTerminals = factory.terminals().list(); 
            for (int index = 0; index < lstTerminals.size(); index ++) {
                CardTerminal ct = lstTerminals.get(index);
                TokenInfo tokenInfo = new TokenInfo();
                tokenInfo.setSlotID(index);
                tokenInfo.setTerminalName(ct.getName());            
                if (ct.isCardPresent() == true) {      
                    tokenInfo.setTokenPresent(true);
                } 
                else {
                    tokenInfo.setTokenPresent(false);
                }
                tableModelTokens.addTokenInfo(tokenInfo);
                logger.info("add tokeninfo:" + tokenInfo);
            }
            logger.info("lstTokens size:" + tableModelTokens.getRowCount());
            jtabTokens.repaint();
        }
        catch (Exception ex) {
            logger.fatal(ex.toString(), ex);
        }
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
        jcmbSignProvider = new javax.swing.JComboBox();
        jtabOperations = new javax.swing.JTabbedPane();
        jpanSign = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        jedtSignInput = new javax.swing.JTextField();
        jbutSignInput = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jedtSignOutput = new javax.swing.JTextField();
        jbutSignOutput = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        jcmbSignType = new javax.swing.JComboBox();
        jbutSign = new javax.swing.JButton();
        jbutAddSign = new javax.swing.JButton();
        jbutCounterSign = new javax.swing.JButton();
        jLabel8 = new javax.swing.JLabel();
        jcmbSignMode = new javax.swing.JComboBox();
        jLabel10 = new javax.swing.JLabel();
        jedtPassword = new javax.swing.JPasswordField();
        jpanMultiSign = new javax.swing.JPanel();
        jLabel6 = new javax.swing.JLabel();
        jedtMultiSignDir = new javax.swing.JTextField();
        jbutMultiSignDir = new javax.swing.JButton();
        jLabel7 = new javax.swing.JLabel();
        jcmbMultiSignType = new javax.swing.JComboBox();
        jbutMultiSign = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        jedtMultiSignOutput = new javax.swing.JTextArea();
        jLabel9 = new javax.swing.JLabel();
        jcmbMultiSignMode = new javax.swing.JComboBox();
        jLabel11 = new javax.swing.JLabel();
        jedtMultiPassword = new javax.swing.JPasswordField();
        jpanVerify = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        jedtVerifyInput = new javax.swing.JTextField();
        jbutVerifyInput = new javax.swing.JButton();
        jbutVerify = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jtabVerifyInfo = new javax.swing.JTable();
        jlabVerifyDataFile = new javax.swing.JLabel();
        jlabVerifyOutput = new javax.swing.JLabel();
        jedtVerifyDataFile = new javax.swing.JTextField();
        jedtVerifyOutput = new javax.swing.JTextField();
        jbutVerifyDataFile = new javax.swing.JButton();
        jbutVerifyOutput = new javax.swing.JButton();
        jpanTrustedCerts = new javax.swing.JPanel();
        jScrollPane4 = new javax.swing.JScrollPane();
        jtabTrustedCerts = new javax.swing.JTable();
        jpanTokens = new javax.swing.JPanel();
        jbutRefreshTokens = new javax.swing.JButton();
        jScrollPane3 = new javax.swing.JScrollPane();
        jtabTokens = new javax.swing.JTable();
        jMenuBar1 = new javax.swing.JMenuBar();
        jmemMain = new javax.swing.JMenu();
        jmitConfig = new javax.swing.JMenuItem();
        jSeparator3 = new javax.swing.JPopupMenu.Separator();
        jmitExit = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("J4OPS");
        setResizable(false);

        jLabel1.setText("SignProvider:");

        jcmbSignProvider.setModel(modelSignProviders);
        jcmbSignProvider.setName(""); // NOI18N
        jcmbSignProvider.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jcmbSignProviderActionPerformed(evt);
            }
        });

        jLabel2.setText("File to Sign:");

        jbutSignInput.setText("...");
        jbutSignInput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutSignInputActionPerformed(evt);
            }
        });

        jLabel3.setText("Output:");

        jbutSignOutput.setText("...");
        jbutSignOutput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutSignOutputActionPerformed(evt);
            }
        });

        jLabel4.setText("Sign Type:");

        jcmbSignType.setModel(modelSignTypes);
        jcmbSignType.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jcmbSignTypeActionPerformed(evt);
            }
        });

        jbutSign.setText("Sign");
        jbutSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutSignActionPerformed(evt);
            }
        });

        jbutAddSign.setText("Add Sign");
        jbutAddSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutAddSignActionPerformed(evt);
            }
        });

        jbutCounterSign.setText("Counter Sign");
        jbutCounterSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutCounterSignActionPerformed(evt);
            }
        });

        jLabel8.setText("Sign Mode:");

        jcmbSignMode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jcmbSignModeActionPerformed(evt);
            }
        });

        jLabel10.setText("Password:");

        javax.swing.GroupLayout jpanSignLayout = new javax.swing.GroupLayout(jpanSign);
        jpanSign.setLayout(jpanSignLayout);
        jpanSignLayout.setHorizontalGroup(
            jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jpanSignLayout.createSequentialGroup()
                .addGap(33, 33, 33)
                .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel10)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3)
                    .addComponent(jLabel4))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jpanSignLayout.createSequentialGroup()
                        .addComponent(jbutSign)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jbutAddSign)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jbutCounterSign))
                    .addGroup(jpanSignLayout.createSequentialGroup()
                        .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jedtSignOutput)
                            .addComponent(jedtSignInput, javax.swing.GroupLayout.DEFAULT_SIZE, 496, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jbutSignOutput, 0, 1, Short.MAX_VALUE)
                            .addComponent(jbutSignInput, javax.swing.GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE)))
                    .addGroup(jpanSignLayout.createSequentialGroup()
                        .addComponent(jcmbSignType, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel8)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jcmbSignMode, javax.swing.GroupLayout.PREFERRED_SIZE, 187, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jedtPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 216, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(69, Short.MAX_VALUE))
        );

        jpanSignLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jbutAddSign, jbutCounterSign, jbutSign});

        jpanSignLayout.setVerticalGroup(
            jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jpanSignLayout.createSequentialGroup()
                .addGap(36, 36, 36)
                .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtSignInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2)
                    .addComponent(jbutSignInput))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel10)
                    .addComponent(jedtPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jedtSignOutput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jbutSignOutput))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jcmbSignType, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4)
                    .addComponent(jLabel8)
                    .addComponent(jcmbSignMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jpanSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jbutSign)
                    .addComponent(jbutAddSign)
                    .addComponent(jbutCounterSign))
                .addContainerGap(129, Short.MAX_VALUE))
        );

        jtabOperations.addTab("Sign", jpanSign);

        jLabel6.setText("Select Directory:");

        jbutMultiSignDir.setText("...");
        jbutMultiSignDir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutMultiSignDirActionPerformed(evt);
            }
        });

        jLabel7.setText("Sign Type:");

        jcmbMultiSignType.setModel(modelSignTypes);

        jbutMultiSign.setText("Sign");
        jbutMultiSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutMultiSignActionPerformed(evt);
            }
        });

        jedtMultiSignOutput.setColumns(20);
        jedtMultiSignOutput.setEditable(false);
        jedtMultiSignOutput.setRows(10);
        jedtMultiSignOutput.setTabSize(2);
        jScrollPane2.setViewportView(jedtMultiSignOutput);

        jLabel9.setText("Sign Mode:");

        jLabel11.setText("Password:");

        javax.swing.GroupLayout jpanMultiSignLayout = new javax.swing.GroupLayout(jpanMultiSign);
        jpanMultiSign.setLayout(jpanMultiSignLayout);
        jpanMultiSignLayout.setHorizontalGroup(
            jpanMultiSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jpanMultiSignLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jpanMultiSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2)
                    .addGroup(jpanMultiSignLayout.createSequentialGroup()
                        .addGroup(jpanMultiSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel7)
                            .addComponent(jLabel6)
                            .addComponent(jLabel11))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jpanMultiSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jpanMultiSignLayout.createSequentialGroup()
                                .addComponent(jedtMultiSignDir, javax.swing.GroupLayout.PREFERRED_SIZE, 510, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jbutMultiSignDir, javax.swing.GroupLayout.PREFERRED_SIZE, 47, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jpanMultiSignLayout.createSequentialGroup()
                                .addComponent(jcmbMultiSignType, javax.swing.GroupLayout.PREFERRED_SIZE, 153, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel9)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jcmbMultiSignMode, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jbutMultiSign, javax.swing.GroupLayout.PREFERRED_SIZE, 66, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jedtMultiPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 201, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 31, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jpanMultiSignLayout.setVerticalGroup(
            jpanMultiSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jpanMultiSignLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jpanMultiSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel6)
                    .addComponent(jedtMultiSignDir, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jbutMultiSignDir))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jpanMultiSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel11)
                    .addComponent(jedtMultiPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jpanMultiSignLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel7)
                    .addComponent(jcmbMultiSignType, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel9)
                    .addComponent(jcmbMultiSignMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jbutMultiSign)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 179, Short.MAX_VALUE)
                .addContainerGap())
        );

        jtabOperations.addTab("Multi Sign", jpanMultiSign);

        jLabel5.setText("File to verify:");

        jbutVerifyInput.setText("...");
        jbutVerifyInput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutVerifyInputActionPerformed(evt);
            }
        });

        jbutVerify.setText("Verify");
        jbutVerify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutVerifyActionPerformed(evt);
            }
        });

        jtabVerifyInfo.setModel(tableModelVerify);
        jtabVerifyInfo.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jtabVerifyInfoMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(jtabVerifyInfo);

        jlabVerifyDataFile.setText("Data File:");
        jlabVerifyDataFile.setEnabled(false);

        jlabVerifyOutput.setText("Output File:");
        jlabVerifyOutput.setEnabled(false);

        jedtVerifyDataFile.setEnabled(false);

        jedtVerifyOutput.setEnabled(false);

        jbutVerifyDataFile.setText("...");
        jbutVerifyDataFile.setEnabled(false);
        jbutVerifyDataFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutVerifyDataFileActionPerformed(evt);
            }
        });

        jbutVerifyOutput.setText("...");
        jbutVerifyOutput.setEnabled(false);
        jbutVerifyOutput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutVerifyOutputActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jpanVerifyLayout = new javax.swing.GroupLayout(jpanVerify);
        jpanVerify.setLayout(jpanVerifyLayout);
        jpanVerifyLayout.setHorizontalGroup(
            jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jpanVerifyLayout.createSequentialGroup()
                .addGroup(jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jpanVerifyLayout.createSequentialGroup()
                        .addGap(12, 12, 12)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 725, Short.MAX_VALUE))
                    .addGroup(jpanVerifyLayout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jlabVerifyOutput, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jlabVerifyDataFile, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel5, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addGap(44, 44, 44)
                        .addGroup(jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jbutVerify, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(jpanVerifyLayout.createSequentialGroup()
                                .addGroup(jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jedtVerifyOutput)
                                    .addComponent(jedtVerifyDataFile)
                                    .addComponent(jedtVerifyInput, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jbutVerifyInput, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jbutVerifyDataFile)
                                    .addComponent(jbutVerifyOutput))))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );

        jpanVerifyLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jbutVerifyDataFile, jbutVerifyInput, jbutVerifyOutput});

        jpanVerifyLayout.setVerticalGroup(
            jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jpanVerifyLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jedtVerifyInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5)
                    .addComponent(jbutVerifyInput))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jlabVerifyDataFile)
                    .addComponent(jedtVerifyDataFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jbutVerifyDataFile))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jpanVerifyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jlabVerifyOutput)
                    .addComponent(jedtVerifyOutput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jbutVerifyOutput))
                .addGap(18, 18, 18)
                .addComponent(jbutVerify)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 163, Short.MAX_VALUE)
                .addContainerGap())
        );

        jtabOperations.addTab("Verify", jpanVerify);

        jtabTrustedCerts.setModel(trustCertsTableModel);
        jtabTrustedCerts.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jtabTrustedCertsMouseClicked(evt);
            }
        });
        jScrollPane4.setViewportView(jtabTrustedCerts);

        javax.swing.GroupLayout jpanTrustedCertsLayout = new javax.swing.GroupLayout(jpanTrustedCerts);
        jpanTrustedCerts.setLayout(jpanTrustedCertsLayout);
        jpanTrustedCertsLayout.setHorizontalGroup(
            jpanTrustedCertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 749, Short.MAX_VALUE)
        );
        jpanTrustedCertsLayout.setVerticalGroup(
            jpanTrustedCertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
        );

        jtabOperations.addTab("Trusted Certs", jpanTrustedCerts);

        jbutRefreshTokens.setText("Refresh");
        jbutRefreshTokens.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbutRefreshTokensActionPerformed(evt);
            }
        });

        jtabTokens.setModel(tableModelTokens);
        jScrollPane3.setViewportView(jtabTokens);

        javax.swing.GroupLayout jpanTokensLayout = new javax.swing.GroupLayout(jpanTokens);
        jpanTokens.setLayout(jpanTokensLayout);
        jpanTokensLayout.setHorizontalGroup(
            jpanTokensLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jpanTokensLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jpanTokensLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jpanTokensLayout.createSequentialGroup()
                        .addComponent(jbutRefreshTokens)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 725, Short.MAX_VALUE))
                .addContainerGap())
        );
        jpanTokensLayout.setVerticalGroup(
            jpanTokensLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jpanTokensLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jbutRefreshTokens)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 295, Short.MAX_VALUE)
                .addContainerGap())
        );

        jtabOperations.addTab("Tokens", jpanTokens);

        jmemMain.setText("File");

        jmitConfig.setText("Config");
        jmitConfig.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jmitConfigActionPerformed(evt);
            }
        });
        jmemMain.add(jmitConfig);
        jmemMain.add(jSeparator3);

        jmitExit.setText("Exit");
        jmitExit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jmitExitActionPerformed(evt);
            }
        });
        jmemMain.add(jmitExit);

        jMenuBar1.add(jmemMain);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addGap(18, 18, 18)
                        .addComponent(jcmbSignProvider, javax.swing.GroupLayout.PREFERRED_SIZE, 163, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(jtabOperations, javax.swing.GroupLayout.Alignment.TRAILING))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jcmbSignProvider, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jtabOperations)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jcmbSignProviderActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jcmbSignProviderActionPerformed
        try {
            SignProvider signProvider = (SignProvider)jcmbSignProvider.getSelectedItem();
            if (signProvider instanceof PKCS11Provider) {
                jtabOperations.setEnabledAt(jtabOperations.getTabCount()-1, true);
                ((PKCS11Provider)signProvider).setTokensConfig(configDialog.getProperty(ConfigDialog.FileConfigPKCS11Tokens));
                refreshTokens();
            }
            else {
                jtabOperations.setEnabledAt(jtabOperations.getTabCount()-1, false);
                ((PKCS12Provider)signProvider).setKetStoreFile(configDialog.getProperty(ConfigDialog.FilePKCS12KeyStore));
            }
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
        }
    }//GEN-LAST:event_jcmbSignProviderActionPerformed

    private void jbutSignActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutSignActionPerformed
        
        SignProvider signProvider = (SignProvider)jcmbSignProvider.getSelectedItem();
        SignType signType = (SignType)jcmbSignType.getSelectedItem();
        Properties prop = configDialog.getProperties();
        FileInputStream fis = null;
        FileOutputStream fos = null;  
        String password = new String (jedtPassword.getPassword());
        if (password != null && password.length() <= 0) password = null;
        try {
            switch (signType) {
                case Pkcs7:
                case CAdES_BES:
                case CAdES_T:
                    
                    if (signType == SignType.Pkcs7) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop);                     
                    CmsSignMode cmsSignMode = CmsSignMode.valueOf((String)jcmbSignMode.getSelectedItem());

                    try {
                        fis = new FileInputStream (jedtSignInput.getText());
                        fos = new FileOutputStream (jedtSignOutput.getText());
                        try {
                            cmsSign.init();
                            cmsSign.sign(new Date(), cmsSignMode, fis, fos); 
                        }
                        finally {
                            cmsSign.destroy();
                        }          
                    }
                    finally {
                        try {
                            if (fis != null) {
                                fis.close();
                                fis = null;
                            }
                        }
                        catch (IOException ex) {}
                        try {
                            if (fos != null) {
                                fos.close();
                                fos = null;
                            }
                        }
                        catch (IOException ex) {}            
                    }                
                    break;
                    
                case PDF:
                case PAdES_BES:
                case PAdES_T:
                                      
                    if (signType == SignType.PDF) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }                  
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    PdfSign pdfSign = new PdfSign (signProvider, signHandler, prop); 

                    try {
                        fis = new FileInputStream (jedtSignInput.getText());
                        fos = new FileOutputStream (jedtSignOutput.getText());
                        try {
                            pdfSign.init();
                            pdfSign.sign(new Date(), fis, password, fos); 
                        }
                        finally {
                            pdfSign.destroy();
                        }         
                    }
                    finally {
                        try {
                            if (fis != null) {
                                fis.close();
                                fis = null;
                            }
                        }
                        catch (IOException ex) {}
                        try {
                            if (fos != null) {
                                fos.close();
                                fos = null;
                            }
                        }
                        catch (IOException ex) {}            
                    }                
                    break;                                        
                    
                case XMLDSIG:
                case XAdES_BES:
                case XAdES_T:
                                            
                    if (signType == SignType.XMLDSIG) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    XmlSign xmlSign = new XmlSign (signProvider, signHandler, prop); 
                    XmlSignMode xmlSignMode = XmlSignMode.valueOf((String)jcmbSignMode.getSelectedItem());                    
                    String baseURI = "";

                    try {
                        fis = new FileInputStream (jedtSignInput.getText());
                        fos = new FileOutputStream (jedtSignOutput.getText());
                        try {
                            xmlSign.init();
                            xmlSign.sign(new Date(), xmlSignMode, baseURI, fis, fos);
                        }
                        finally {
                            xmlSign.destroy();
                        }                          
                    }
                    finally {
                        try {
                            if (fis != null) {
                                fis.close();
                                fis = null;
                            }
                        }
                        catch (IOException ex) {}
                        try {
                            if (fos != null) {
                                fos.close();
                                fos = null;
                            }
                        }
                        catch (IOException ex) {}            
                    }                
                    break;              
            }
            JOptionPane.showMessageDialog(J4OPSMainForm.this, "Sign Complited!");
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.toString());
        }
    }//GEN-LAST:event_jbutSignActionPerformed

    private void jbutAddSignActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutAddSignActionPerformed
        SignProvider signProvider = (SignProvider)jcmbSignProvider.getSelectedItem();
        SignType signType = (SignType)jcmbSignType.getSelectedItem();
        Properties prop = configDialog.getProperties();
        FileInputStream fis = null;
        FileOutputStream fos = null;     
        String password = new String (jedtPassword.getPassword());
        if (password != null && password.length() <= 0) password = null;
        try {
            switch (signType) {
                case Pkcs7:
                case CAdES_BES:
                case CAdES_T:
                                           
                    if (signType == SignType.Pkcs7) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop); 
                    CmsSignMode cmsSignMode = CmsSignMode.valueOf((String)jcmbSignMode.getSelectedItem());
                    
                    try {
                        fis = new FileInputStream (jedtSignInput.getText());
                        fos = new FileOutputStream (jedtSignOutput.getText());  
                        try {
                            cmsSign.init();
                            cmsSign.addSign(new Date(), cmsSignMode, fis, fos); 
                        }
                        finally {
                            cmsSign.destroy();
                        }                        
                    }
                    finally {
                        try {
                            if (fis != null) {
                                fis.close();
                                fis = null;
                            }
                        }
                        catch (IOException ex) {}
                        try {
                            if (fos != null) {
                                fos.close();
                                fos = null;
                            }
                        }
                        catch (IOException ex) {}            
                    }                
                    break;
                    
                case PDF:
                case PAdES_BES:
                case PAdES_T:
                                        
                    if (signType == SignType.PDF) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    PdfSign pdfSign = new PdfSign (signProvider, signHandler, prop); 

                    try {
                        fis = new FileInputStream (jedtSignInput.getText());
                        fos = new FileOutputStream (jedtSignOutput.getText());
                        try {
                            pdfSign.init();
                            pdfSign.addSign(new Date(), fis, password, fos); 
                        }
                        finally {
                            pdfSign.destroy();
                        }                        
                    }
                    finally {
                        try {
                            if (fis != null) {
                                fis.close();
                                fis = null;
                            }
                        }
                        catch (IOException ex) {}
                        try {
                            if (fos != null) {
                                fos.close();
                                fos = null;
                            }
                        }
                        catch (IOException ex) {}            
                    }                
                    break;                                        
                    
                case XMLDSIG:
                case XAdES_BES:
                case XAdES_T:
                                      
                    if (signType == SignType.XMLDSIG) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    XmlSign xmlSign = new XmlSign (signProvider, signHandler, prop); 
                    XmlSignMode xmlSignMode = XmlSignMode.valueOf((String)jcmbSignMode.getSelectedItem());                    
                    String baseURI = "";
                    
                    try {
                        fis = new FileInputStream (jedtSignInput.getText());
                        fos = new FileOutputStream (jedtSignOutput.getText());
                        try {
                            xmlSign.init();
                            xmlSign.addSign(new Date(), xmlSignMode, baseURI, fis, fos);
                        }
                        finally {
                            xmlSign.destroy();
                        }                          
                    }
                    finally {
                        try {
                            if (fis != null) {
                                fis.close();
                                fis = null;
                            }
                        }
                        catch (IOException ex) {}
                        try {
                            if (fos != null) {
                                fos.close();
                                fos = null;
                            }
                        }
                        catch (IOException ex) {}            
                    }                
                    break;              
            }
            JOptionPane.showMessageDialog(J4OPSMainForm.this, "Add Sign Complited!");
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.toString());
        }
    }//GEN-LAST:event_jbutAddSignActionPerformed

    private void jbutCounterSignActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutCounterSignActionPerformed
        SignProvider signProvider = (SignProvider)jcmbSignProvider.getSelectedItem();
        SignType signType = (SignType)jcmbSignType.getSelectedItem();
        Properties prop = configDialog.getProperties();
        FileInputStream fis = null;
        FileOutputStream fos = null;        
        try {
            switch (signType) {
                case Pkcs7:
                case CAdES_BES:
                case CAdES_T:
                                               
                    if (signType == SignType.Pkcs7) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop); 
                    CmsSignMode cmsSignMode = CmsSignMode.valueOf((String)jcmbSignMode.getSelectedItem());
                    
                    try {
                        fis = new FileInputStream (jedtSignInput.getText());
                        fos = new FileOutputStream (jedtSignOutput.getText());
                        try {
                            cmsSign.init();
                            cmsSign.counterSign(new Date(), cmsSignMode, fis, fos); 
                        }
                        finally {
                            cmsSign.destroy();
                        }
                    }
                    finally {
                        try {
                            if (fis != null) {
                                fis.close();
                                fis = null;
                            }
                        }
                        catch (IOException ex) {}
                        try {
                            if (fos != null) {
                                fos.close();
                                fos = null;
                            }
                        }
                        catch (IOException ex) {}            
                    }                
                    break;             
            }
            JOptionPane.showMessageDialog(J4OPSMainForm.this, "Counter Sign Complited!");
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.toString());
        }
    }//GEN-LAST:event_jbutCounterSignActionPerformed

    private void jcmbSignTypeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jcmbSignTypeActionPerformed
        
        DefaultComboBoxModel modelSignMode = null;
        String inputFile = jedtSignInput.getText();
        SignType signType = (SignType)jcmbSignType.getSelectedItem();
        switch (signType) {
            case Pkcs7:
            case CAdES_BES: 
            case CAdES_T:   
                
                modelSignMode = new DefaultComboBoxModel(new String[]{CmsSignMode.Attached.toString(), 
                                                                      CmsSignMode.Detached.toString()});
                jcmbSignMode.setModel (modelSignMode);
                jcmbSignMode.setEnabled(true);
                jcmbMultiSignMode.setModel (modelSignMode);
                jcmbMultiSignMode.setEnabled(true);                

                jbutCounterSign.setEnabled(true);
                if (inputFile != null && !inputFile.equals("")) {
                    inputFile = inputFile.substring(0, inputFile.lastIndexOf("."));
                    jedtSignOutput.setText(inputFile + "_sign.p7m");
                }
                break;
                
            case PDF:
            case PAdES_BES: 
            case PAdES_T:      
                
                jcmbSignMode.setEnabled(false);
                jcmbMultiSignMode.setEnabled(false);                 
                
                jbutCounterSign.setEnabled(false);
                if (inputFile != null && !inputFile.equals("")) {
                    inputFile = inputFile.substring(0, inputFile.lastIndexOf("."));
                    jedtSignOutput.setText(inputFile + "_sign.pdf");
                }                
                break;
                
            case XMLDSIG:
            case XAdES_BES:
            case XAdES_T:        
                
                modelSignMode = new DefaultComboBoxModel(new String[]{XmlSignMode.Enveloped.toString(), 
                                                                      XmlSignMode.Enveloping.toString(), 
                                                                      XmlSignMode.Detached.toString()});
                jcmbSignMode.setModel (modelSignMode);
                jcmbSignMode.setEnabled(true); 
                jcmbMultiSignMode.setModel (modelSignMode);
                jcmbMultiSignMode.setEnabled(true);                 
                
                jbutCounterSign.setEnabled(false);
                if (inputFile != null && !inputFile.equals("")) {
                    inputFile = inputFile.substring(0, inputFile.lastIndexOf("."));
                    jedtSignOutput.setText(inputFile + "_sign.xml");
                }                  
                break;
        }
    }//GEN-LAST:event_jcmbSignTypeActionPerformed

    private void jmitConfigActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jmitConfigActionPerformed
        configDialog.setVisible(true);
        
        try {
            // reload trusted certs
            reloadTrustCerts ();
        }
        catch (Exception ex) {
            logger.fatal(ex.toString(), ex);
        }
    }//GEN-LAST:event_jmitConfigActionPerformed

    private void jbutSignInputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutSignInputActionPerformed

        try {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
            int returnVal = chooser.showOpenDialog(J4OPSMainForm.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String path = chooser.getCurrentDirectory().getCanonicalPath();
                path = path + System.getProperty("file.separator") + chooser.getSelectedFile().getName();
                jedtSignInput.setText(path);
                jcmbSignType.setSelectedItem(jcmbSignType.getSelectedItem());
            }
        }
        catch (IOException ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.getMessage());
        } 
          
    }//GEN-LAST:event_jbutSignInputActionPerformed

    private void jbutSignOutputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutSignOutputActionPerformed
        try {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setAcceptAllFileFilterUsed(false);
            int returnVal = chooser.showOpenDialog(J4OPSMainForm.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String path = chooser.getCurrentDirectory().getCanonicalPath();
                path = path + System.getProperty("file.separator") + chooser.getSelectedFile().getName();
                String inputFile = jedtSignInput.getText();
                if (inputFile != null && !inputFile.equals("")) {
                    inputFile = inputFile.substring(inputFile.lastIndexOf(System.getProperty("file.separator")));
                    inputFile = inputFile.substring(0, inputFile.lastIndexOf("."));
                    SignType signType = (SignType)jcmbSignType.getSelectedItem();
                    switch (signType) {
                        case Pkcs7:
                        case CAdES_BES:
                        case CAdES_T:            
                            CmsSignMode cmsSignMode = CmsSignMode.valueOf((String)jcmbSignMode.getSelectedItem());
                            if (cmsSignMode == CmsSignMode.Detached) {
                                jedtSignOutput.setText(path + inputFile + "_sign.p7s");
                            }
                            else {
                                jedtSignOutput.setText(path + inputFile + "_sign.p7m");                            
                            }
                            break;                            
                            
                        case PDF:
                        case PAdES_BES: 
                        case PAdES_T:                            
                            jedtSignOutput.setText(path + inputFile + "_sign.pdf");
                            break;

                        case XMLDSIG:
                        case XAdES_BES:
                        case XAdES_T:                            
                            jedtSignOutput.setText(path + inputFile + "_sign.xml");
                            break;
                    }                            
                }
                
            }
        }
        catch (IOException ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.getMessage());
        } 
    }//GEN-LAST:event_jbutSignOutputActionPerformed

    private void jmitExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jmitExitActionPerformed
        dispose();
    }//GEN-LAST:event_jmitExitActionPerformed

    private void jbutVerifyInputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutVerifyInputActionPerformed
        try {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
            int returnVal = chooser.showOpenDialog(J4OPSMainForm.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String path = chooser.getCurrentDirectory().getCanonicalPath();
                path = path + System.getProperty("file.separator") + chooser.getSelectedFile().getName();
                jedtVerifyInput.setText(path);
                String fileInputExt = path.substring(path.lastIndexOf("."));
                if (fileInputExt.equalsIgnoreCase(".P7M")) {
                    jlabVerifyDataFile.setEnabled(false);
                    jedtVerifyDataFile.setEnabled(false);
                    jbutVerifyDataFile.setEnabled(false);
                    jlabVerifyOutput.setEnabled(true);
                    jedtVerifyOutput.setEnabled(true);
                    jbutVerifyOutput.setEnabled(true);
                }
                else if (fileInputExt.equalsIgnoreCase(".P7S")) {
                    jlabVerifyDataFile.setEnabled(true);
                    jedtVerifyDataFile.setEnabled(true);
                    jbutVerifyDataFile.setEnabled(true);
                    jlabVerifyOutput.setEnabled(false);
                    jedtVerifyOutput.setEnabled(false);
                    jbutVerifyOutput.setEnabled(false);                    
                }
                else if (fileInputExt.equalsIgnoreCase(".PDF")) {
                    jlabVerifyDataFile.setEnabled(false);
                    jedtVerifyDataFile.setEnabled(false);
                    jbutVerifyDataFile.setEnabled(false);
                    jlabVerifyOutput.setEnabled(false);
                    jedtVerifyOutput.setEnabled(false);
                    jbutVerifyOutput.setEnabled(false);                     
                }
                else if (fileInputExt.equalsIgnoreCase(".XML")) { 
                    jlabVerifyDataFile.setEnabled(false);
                    jedtVerifyDataFile.setEnabled(false);
                    jbutVerifyDataFile.setEnabled(false);
                    jlabVerifyOutput.setEnabled(false);
                    jedtVerifyOutput.setEnabled(false);
                    jbutVerifyOutput.setEnabled(false);                    
                }
            }
        }
        catch (IOException ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.getMessage());
        } 
    }//GEN-LAST:event_jbutVerifyInputActionPerformed

    private List<SignerInfo> getSignerInfos(List<SignerInfo> lstSignerInfos, SignerInfo signerInfo) {
        for (SignerInfo si : signerInfo.getSignerInfos()) {
            lstSignerInfos.add(si);
            getSignerInfos (lstSignerInfos, si);
        }        
        return lstSignerInfos;
    }
    
    
    private void jbutVerifyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutVerifyActionPerformed
        String fileEnvelope = jedtVerifyInput.getText();
        if (fileEnvelope == null || fileEnvelope.equals("")) {
            return;
        }
        String fileEnvelopeExt = fileEnvelope.substring(fileEnvelope.lastIndexOf("."));
        VerifyInfo verifyInfo = null;
        FileInputStream fisEnvelope = null;
        FileInputStream fisData = null;        
        FileOutputStream fos = null;
        Properties prop = configDialog.getProperties();
        try {
            fisEnvelope = new FileInputStream (fileEnvelope);
            if (fileEnvelopeExt.equalsIgnoreCase(".P7M")) {
                fos = new FileOutputStream (jedtVerifyOutput.getText());
                CmsVerify cmsVerify = new CmsVerify (prop);  
                verifyInfo = cmsVerify.verify(fisEnvelope, null, fos);
            }
            else if (fileEnvelopeExt.equalsIgnoreCase(".P7S")) {
                fisData = new FileInputStream (jedtVerifyDataFile.getText());
                CmsVerify cmsVerify = new CmsVerify (prop);  
                verifyInfo = cmsVerify.verify(fisEnvelope, fisData, null);
            }            
            else if (fileEnvelopeExt.equalsIgnoreCase(".PDF")) {
                PdfVerify pdfVerify = new PdfVerify (prop);
                verifyInfo = pdfVerify.verify(fisEnvelope);
            }
            else if (fileEnvelopeExt.equalsIgnoreCase(".XML")) {      
                XmlVerify xmlVerify = new XmlVerify (prop);
                verifyInfo = xmlVerify.verify(fisEnvelope);
            }
            if (verifyInfo != null) {
                List<SignerInfo> lstSignerInfos = new ArrayList<SignerInfo>();
                for (SignerInfo signerInfo : verifyInfo.getSignerInfos()) {
                    lstSignerInfos.add(signerInfo);
                    getSignerInfos (lstSignerInfos, signerInfo);
                }
                tableModelVerify.removeAll();
                for (SignerInfo signerInfo : lstSignerInfos) {
                    tableModelVerify.addSignerInfo(signerInfo);
                }                
            }            
            JOptionPane.showMessageDialog(J4OPSMainForm.this, "Verify Complited!");
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.toString());
        }
        finally {
            try {
                if (fisEnvelope != null) {
                    fisEnvelope.close();
                    fisEnvelope = null;
                }
            }
            catch(Exception e) {}
            try {
                if (fisData != null) {
                    fisData.close();
                    fisData = null;
                }
            }
            catch(Exception e) {}            
            try {
                if (fos != null) {
                    fos.close();
                    fos = null;
                }
            }
            catch(Exception e) {}            
        }
    }//GEN-LAST:event_jbutVerifyActionPerformed

    private void jbutVerifyDataFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutVerifyDataFileActionPerformed

        try {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
            int returnVal = chooser.showOpenDialog(J4OPSMainForm.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String path = chooser.getCurrentDirectory().getCanonicalPath();
                path = path + System.getProperty("file.separator") + chooser.getSelectedFile().getName();
                jedtVerifyDataFile.setText(path);
            }
        }
        catch (IOException ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.getMessage());
        }        
        
    }//GEN-LAST:event_jbutVerifyDataFileActionPerformed

    private void jbutVerifyOutputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutVerifyOutputActionPerformed
        try {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setAcceptAllFileFilterUsed(false);
            int returnVal = chooser.showOpenDialog(J4OPSMainForm.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String path = chooser.getCurrentDirectory().getCanonicalPath();
                path = path + System.getProperty("file.separator") + chooser.getSelectedFile().getName();
                String inputFile = jedtVerifyInput.getText();
                if (inputFile != null && !inputFile.equals("")) {
                    inputFile = inputFile.substring(inputFile.lastIndexOf(System.getProperty("file.separator")));
                    inputFile = inputFile.substring(0, inputFile.lastIndexOf("."));
                    jedtVerifyOutput.setText(path + inputFile + "_verified.pdf");        
                }
            }
        }
        catch (IOException ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.getMessage());
        }
    }//GEN-LAST:event_jbutVerifyOutputActionPerformed

    private void jbutMultiSignDirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutMultiSignDirActionPerformed
        try {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setAcceptAllFileFilterUsed(false);
            int returnVal = chooser.showOpenDialog(J4OPSMainForm.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                String path = chooser.getCurrentDirectory().getCanonicalPath();
                path = path + System.getProperty("file.separator") + chooser.getSelectedFile().getName();
                jedtMultiSignDir.setText(path);
            }
        }
        catch (IOException ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.getMessage());
        }                
    }//GEN-LAST:event_jbutMultiSignDirActionPerformed

    public File[] findFiles(File root, final String ext) {
        return root.listFiles(new FileFilter() {
            @Override
            public boolean accept(File f) {
                return f.isFile() && !f.getName().endsWith("_sign.p7m")
                                  && !f.getName().endsWith("_sign.pdf")
                                  && !f.getName().endsWith("_sign.xml")
                                  && (ext == null || f.getName().endsWith(ext));
            }
        });
    }    
    
    private void jbutMultiSignActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutMultiSignActionPerformed
        SignProvider signProvider = (SignProvider)jcmbSignProvider.getSelectedItem();
        Properties prop = configDialog.getProperties();
        FileInputStream fis = null;
        FileOutputStream fos = null; 
        jedtMultiSignOutput.setText("Multi Sign");
        SignType signType = (SignType)jcmbMultiSignType.getSelectedItem();  
        String password = new String (jedtMultiPassword.getPassword());
        if (password != null && password.length() <= 0) password = null;        
        try {
            switch (signType) {
                case Pkcs7:
                case CAdES_BES:
                case CAdES_T:
                    
                    if (signType == SignType.Pkcs7) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    } 
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    CmsSign cmsSign = new CmsSign (signProvider, signHandler, prop); 
                    CmsSignMode cmsSignMode = CmsSignMode.valueOf((String)jcmbMultiSignMode.getSelectedItem());                    

                    try {
                        cmsSign.init();
                        File []filesInDir = findFiles (new File(jedtMultiSignDir.getText()), null);
                        for (File f : filesInDir) {
                            String inputFile = f.getAbsolutePath();
                            String outputFile = f.getAbsolutePath().substring(0, f.getAbsolutePath().lastIndexOf("."));                            
                            if (cmsSignMode == CmsSignMode.Detached) {
                                outputFile += "_sign.p7s";
                            }
                            else {
                                outputFile += "_sign.p7m";
                            }
                            
                            jedtMultiSignOutput.setText(jedtMultiSignOutput.getText() + System.getProperty("line.separator") + "Sign " + inputFile);
                            fis = new FileInputStream (inputFile);
                            fos = new FileOutputStream (outputFile);                                                
                            try {
                                cmsSign.sign(new Date(), cmsSignMode, fis, fos); 
                            }
                            finally {
                                try {
                                    if (fis != null) {
                                        fis.close();
                                        fis = null;
                                    }
                                }
                                catch (IOException ex) {}
                                try {
                                    if (fos != null) {
                                        fos.close();
                                        fos = null;
                                    }
                                }
                                catch (IOException ex) {}            
                            }                             
                        }
                    }
                    finally {
                        cmsSign.destroy();
                    }          
                    break;                            

                case PDF:
                case PAdES_BES: 
                case PAdES_T:
                    
                    if (signType == SignType.PDF) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    PdfSign pdfSign = new PdfSign (signProvider, signHandler, prop); 

                    try {
                        pdfSign.init();
                        File []filesInDir = findFiles (new File(jedtMultiSignDir.getText()), "pdf");
                        for (File f : filesInDir) {
                            String inputFile = f.getAbsolutePath();
                            String outputFile = f.getAbsolutePath().substring(0, f.getAbsolutePath().lastIndexOf(".")) + "_sign.pdf";                            

                            jedtMultiSignOutput.setText(jedtMultiSignOutput.getText() + System.getProperty("line.separator") + "Sign " + inputFile);
                            fis = new FileInputStream (inputFile);
                            fos = new FileOutputStream (outputFile);                                                
                            try {
                                pdfSign.sign(new Date(), fis, password, fos); 
                            }
                            finally {
                                try {
                                    if (fis != null) {
                                        fis.close();
                                        fis = null;
                                    }
                                }
                                catch (IOException ex) {}
                                try {
                                    if (fos != null) {
                                        fos.close();
                                        fos = null;
                                    }
                                }
                                catch (IOException ex) {}            
                            }                             
                        }
                    }
                    finally {
                        pdfSign.destroy();
                    }  
                    break;

                case XMLDSIG:
                case XAdES_BES:
                case XAdES_T:
                    
                    if (signType == SignType.XMLDSIG) {
                        prop.setProperty(DigestAlgName.getLiteral(), "SHA1"); 
                    }
                    prop.setProperty(EnvelopeSignType.getLiteral(), signType.toString());
                    XmlSign xmlSign = new XmlSign (signProvider, signHandler, prop); 
                    XmlSignMode xmlSignMode = XmlSignMode.valueOf((String)jcmbMultiSignMode.getSelectedItem());                    
                    String baseURI = "";
                    
                    try {
                        xmlSign.init();
                        File []filesInDir = findFiles (new File(jedtMultiSignDir.getText()), "xml");
                        for (File f : filesInDir) {
                            String inputFile = f.getAbsolutePath();
                            String outputFile = f.getAbsolutePath().substring(0, f.getAbsolutePath().lastIndexOf(".")) + "_sign.xml";                            

                            jedtMultiSignOutput.setText(jedtMultiSignOutput.getText() + System.getProperty("line.separator") + "Sign " + inputFile);                            
                            fis = new FileInputStream (inputFile);
                            fos = new FileOutputStream (outputFile);                                                
                            try {
                                xmlSign.sign(new Date(), xmlSignMode, baseURI, fis, fos); 
                            }
                            finally {
                                try {
                                    if (fis != null) {
                                        fis.close();
                                        fis = null;
                                    }
                                }
                                catch (IOException ex) {}
                                try {
                                    if (fos != null) {
                                        fos.close();
                                        fos = null;
                                    }
                                }
                                catch (IOException ex) {}            
                            }                             
                        }
                    }
                    finally {
                        xmlSign.destroy();
                    }  
                    break;
            }     
            jedtMultiSignOutput.setText(jedtMultiSignOutput.getText() + System.getProperty("line.separator") + "Complited!");
            JOptionPane.showMessageDialog(J4OPSMainForm.this, "Multi Sign Complited!");
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(J4OPSMainForm.this, ex.toString());
        }
    }//GEN-LAST:event_jbutMultiSignActionPerformed

    private void jbutRefreshTokensActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbutRefreshTokensActionPerformed
        try {
            refreshTokens();
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
        }
    }//GEN-LAST:event_jbutRefreshTokensActionPerformed

    private void jtabTrustedCertsMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jtabTrustedCertsMouseClicked

        if (evt.getClickCount() == 2){
            int row = jtabTrustedCerts.getSelectedRow();
            X509Certificate x509Cert = ((CertificateTableModel)jtabTrustedCerts.getModel()).getCertificate(row);
            try {
                JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
                int returnVal = chooser.showOpenDialog(null);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    String path = chooser.getCurrentDirectory().getCanonicalPath();
                    path = path + System.getProperty("file.separator") + chooser.getSelectedFile().getName();

                    FileOutputStream fos = null;
                    try {
                        fos = new FileOutputStream (path);
                        fos.write(x509Cert.getEncoded());
                        fos.flush();
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
            }
            catch (Exception ex) {
                logger.fatal(ex.getMessage(), ex);
                JOptionPane.showMessageDialog(null, ex.getMessage());
            }             
        }
    }//GEN-LAST:event_jtabTrustedCertsMouseClicked

    private void jcmbSignModeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jcmbSignModeActionPerformed
        
        String inputFile = jedtSignInput.getText();
        SignType signType = (SignType)jcmbSignType.getSelectedItem();        
        try {
            switch (signType) {
                case Pkcs7:
                case CAdES_BES:
                case CAdES_T:
                    
                    CmsSignMode cmsSignMode = CmsSignMode.valueOf((String)jcmbSignMode.getSelectedItem()); 
                    if (inputFile != null && !inputFile.equals("")) {
                        inputFile = inputFile.substring(0, inputFile.lastIndexOf("."));
                        if (cmsSignMode == CmsSignMode.Detached) {
                            jedtSignOutput.setText(inputFile + "_sign.p7s");
                        }
                        else {
                            jedtSignOutput.setText(inputFile + "_sign.p7m");
                        }
                    }                    
            }
        }
        catch (Exception ex) {
            logger.fatal(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(null, ex.getMessage());
        }                
    }//GEN-LAST:event_jcmbSignModeActionPerformed

    private void jtabVerifyInfoMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jtabVerifyInfoMouseClicked
        if (evt.getClickCount() == 2){
            int row = jtabVerifyInfo.getSelectedRow();
            X509Certificate x509Cert = ((VerifyTableModel)jtabVerifyInfo.getModel()).getCertificate(row);
            try {
                JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
                int returnVal = chooser.showOpenDialog(null);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    String path = chooser.getCurrentDirectory().getCanonicalPath();
                    path = path + System.getProperty("file.separator") + chooser.getSelectedFile().getName();

                    FileOutputStream fos = null;
                    try {
                        fos = new FileOutputStream (path);
                        fos.write(x509Cert.getEncoded());
                        fos.flush();
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
            }
            catch (Exception ex) {
                logger.fatal(ex.getMessage(), ex);
                JOptionPane.showMessageDialog(null, ex.getMessage());
            }             
        }
    }//GEN-LAST:event_jtabVerifyInfoMouseClicked

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
            java.util.logging.Logger.getLogger(J4OPSMainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(J4OPSMainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(J4OPSMainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(J4OPSMainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {

            @Override
            public void run() {
             
                try {
                    URL url = getClass().getResource("/log4j.xml");
                    if (url != null) {
                        DOMConfigurator.configure(url);        
                    }
                    new J4OPSMainForm().setVisible(true);
                }
                catch (Exception ex) {
                    logger.fatal(ex.toString(), ex);
                }
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JPopupMenu.Separator jSeparator3;
    private javax.swing.JButton jbutAddSign;
    private javax.swing.JButton jbutCounterSign;
    private javax.swing.JButton jbutMultiSign;
    private javax.swing.JButton jbutMultiSignDir;
    private javax.swing.JButton jbutRefreshTokens;
    private javax.swing.JButton jbutSign;
    private javax.swing.JButton jbutSignInput;
    private javax.swing.JButton jbutSignOutput;
    private javax.swing.JButton jbutVerify;
    private javax.swing.JButton jbutVerifyDataFile;
    private javax.swing.JButton jbutVerifyInput;
    private javax.swing.JButton jbutVerifyOutput;
    private javax.swing.JComboBox jcmbMultiSignMode;
    private javax.swing.JComboBox jcmbMultiSignType;
    private javax.swing.JComboBox jcmbSignMode;
    private javax.swing.JComboBox jcmbSignProvider;
    private javax.swing.JComboBox jcmbSignType;
    private javax.swing.JPasswordField jedtMultiPassword;
    private javax.swing.JTextField jedtMultiSignDir;
    private javax.swing.JTextArea jedtMultiSignOutput;
    private javax.swing.JPasswordField jedtPassword;
    private javax.swing.JTextField jedtSignInput;
    private javax.swing.JTextField jedtSignOutput;
    private javax.swing.JTextField jedtVerifyDataFile;
    private javax.swing.JTextField jedtVerifyInput;
    private javax.swing.JTextField jedtVerifyOutput;
    private javax.swing.JLabel jlabVerifyDataFile;
    private javax.swing.JLabel jlabVerifyOutput;
    private javax.swing.JMenu jmemMain;
    private javax.swing.JMenuItem jmitConfig;
    private javax.swing.JMenuItem jmitExit;
    private javax.swing.JPanel jpanMultiSign;
    private javax.swing.JPanel jpanSign;
    private javax.swing.JPanel jpanTokens;
    private javax.swing.JPanel jpanTrustedCerts;
    private javax.swing.JPanel jpanVerify;
    private javax.swing.JTabbedPane jtabOperations;
    private javax.swing.JTable jtabTokens;
    private javax.swing.JTable jtabTrustedCerts;
    private javax.swing.JTable jtabVerifyInfo;
    // End of variables declaration//GEN-END:variables
}


class TokenInfoTableModel extends DefaultTableModel {    
    
    public TokenInfoTableModel () {
        setDataVector(new Object[0][0], new String[]{"SlotID", "TerminalName", "isTokenPresent"});
    }

    public void removeAll () {
        for (int index = 0; index < getRowCount(); index++) {
            removeRow(index);      
        }
        getDataVector().clear();
    }
    
    public void addTokenInfo (TokenInfo tokenInfo) {
        insertRow(getRowCount(), new String[]{"" + tokenInfo.getSlotID(), tokenInfo.getTerminalName(), "" + tokenInfo.isTokenPresent()});       
    }  
    
    @Override
    public boolean isCellEditable(int row, int column) {
       return false;
    }    
}

class VerifyTableModel extends DefaultTableModel {    
    private List<X509Certificate> lstCerts = new ArrayList<X509Certificate>();
    
    public VerifyTableModel () {
        setDataVector(new Object[0][0], new String[]{"Level", "Owner", "Organization", "Issuer", "DateSign", "SignType", "isCounterSign", "GetCert"});
    }
    
    public X509Certificate getCertificate (int row) {
        return lstCerts.get(row);
    }  
    
    public void removeAll () {
        for (int index = 0; index < getRowCount(); index++) {
            removeRow(index);      
        }
        getDataVector().clear();
        lstCerts.clear();
    }
    
    public void addSignerInfo (SignerInfo signerInfo) {
        SimpleDateFormat sdf = new SimpleDateFormat ("dd-MM-yyyy HH:mm:ss");
        insertRow(getRowCount(), new Object[]{"" + signerInfo.getLevel(),
                                              signerInfo.getAuthor(),
                                              DNParser.parse(signerInfo.getX509Cert().getSubjectDN().toString(), "O"),
                                              DNParser.parse(signerInfo.getX509Cert().getIssuerDN().toString(), "CN"),
                                              sdf.format(signerInfo.getDateSign()),
                                              "" + signerInfo.getSignType(),
                                              "" + signerInfo.isCounterSignature(),
                                              new ImageIcon(getClass().getClassLoader().getResource("images/certificate.gif"))});       
        
        lstCerts.add(signerInfo.getX509Cert());        
    } 
    
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if ((getColumnCount() - 1) == columnIndex) {
            return ImageIcon.class;
        }
        else {
            return String.class;
        }
    }    
    
    @Override
    public boolean isCellEditable(int row, int column) {
       return false;
    }                        
}


class CertificateTableModel extends DefaultTableModel {  
    private List<X509Certificate> lstCerts = new ArrayList<X509Certificate>();
    
    public CertificateTableModel () {
        setDataVector(new Object[0][], 
            new String[]{"Index", "Owner", "SerialNumber", "Organization", "Issuer", "NotBefore", "NotAfter", "GetCert"});     
    } 
    
    public X509Certificate getCertificate (int row) {
        return lstCerts.get(row);
    }
    
    public void removeAll () {
        for (int index = 0; index < getRowCount(); index++) {
            removeRow(index);      
        }
        getDataVector().clear();
        lstCerts.clear();
    }
    
    public void addX509Certificate (X509Certificate cert) {
        SimpleDateFormat sdf = new SimpleDateFormat ("dd-MM-yyyy HH:mm:ss");
        int row = getRowCount();
        insertRow(row, new Object[]{Integer.toString(row),
                                    DNParser.parse(cert.getSubjectDN().toString(), "CN"),
                                    DNParser.parse(cert.getSubjectDN().toString(), "SERIALNUMBER"),
                                    DNParser.parse(cert.getSubjectDN().toString(), "O"),
                                    DNParser.parse(cert.getIssuerDN().toString(), "CN"),
                                    sdf.format(cert.getNotBefore()),
                                    sdf.format(cert.getNotAfter()),
                                    new ImageIcon(getClass().getClassLoader().getResource("images/certificate.gif"))});
        lstCerts.add(cert);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if ((getColumnCount() - 1) == columnIndex) {
            return ImageIcon.class;
        }
        else {
            return String.class;
        }
    }
    
    @Override
    public boolean isCellEditable(int row, int column) {
       return false;
    }    
                         
}