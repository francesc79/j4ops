/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.test;

import it.j4ops.util.X509Util;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import junit.framework.TestCase;
import junit.swingui.TestRunner;
import org.apache.log4j.xml.DOMConfigurator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestHolder;

public class GeneratePKCS12 extends TestCase {
    
	private static final String SIG_ALG_NAME = "SHA256withRSA";    
    
	// Validity for the certificate, in days
	private static final int VALIDITY = 365;    
    
    public static X509Certificate generateV3Certificate(String cn, BigInteger sn, Date firstDate, Date lastDate, KeyPair pair, int keyusage, boolean isCa)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException,
            OperatorCreationException, CertificateException {   

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALG_NAME);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        
        X500Principal subject = new X500Principal(cn);
        PKCS10CertificationRequest inputCSR = new PKCS10CertificationRequest (SIG_ALG_NAME, subject, pair.getPublic(), null, pair.getPrivate());        
                
        AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

      
        
        PKCS10CertificationRequestHolder pk10Holder = new PKCS10CertificationRequestHolder(inputCSR);
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                new X500Name(cn), sn, firstDate, lastDate, pk10Holder.getSubject(), keyInfo);

        BasicConstraints constrains = new BasicConstraints(false);
        if (isCa) {
            constrains = new BasicConstraints(true);
        }        
        
        certGen.addExtension(X509Extension.basicConstraints, true, constrains);
        certGen.addExtension(X509Extension.keyUsage, true, new KeyUsage(keyusage));
        //certGen.addExtension(X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        certGen.addExtension(X509Extension.subjectAlternativeName, false, new GeneralNames(
            new GeneralName(GeneralName.rfc822Name, "francesco.zanutto@gmail.com")));        

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(foo);        

        X509CertificateHolder holder = certGen.build(sigGen);
        X509CertificateStructure eeX509CertificateStructure = holder.toASN1Structure(); 

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Read Certificate
        InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
        X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
        is1.close();
        return theCert;
    }    
    
   public static int getIntKeyUsage(boolean keyUsage[]) {
        int iku = 0;
     
        for (int i = 0; i < keyUsage.length; i++) {           
            if (keyUsage[i]) {
                iku = iku | (0x80>>>i);
            }
        }
        return iku;
    }    
    
    private static X509Certificate signCertificate(X509Certificate selfsigned, X509Certificate issuercert, PrivateKey key, String sigalg, boolean isCa)
            throws GeneralSecurityException, OperatorCreationException, IOException {

        Principal ip = issuercert.getSubjectDN();
        Principal sp = selfsigned.getSubjectDN();
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                new X500Name(ip.getName()),
                selfsigned.getSerialNumber(), selfsigned.getNotBefore(), selfsigned.getNotAfter(),
                new X500Name(sp.getName()), selfsigned.getPublicKey());
        BasicConstraints constrains = new BasicConstraints(false);
        if (isCa) {
            constrains = new BasicConstraints(true);
        }        
        certGen.addExtension(X509Extension.basicConstraints, true, constrains);
        certGen.addExtension(X509Extension.keyUsage, true, new KeyUsage(getIntKeyUsage(selfsigned.getKeyUsage())));        
        
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder(sigalg);
        builder.setProvider("BC");
        ContentSigner signr = builder.build(key);
        X509CertificateHolder certHolder = certGen.build(signr);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream in = new ByteArrayInputStream(certHolder.getEncoded());
        try {
            return (X509Certificate)cf.generateCertificate(in);
        } finally {
            in.close();
        }
    }

    public static void createKeyStoreCA (X509Certificate certCA) throws Exception {
        
        String keyFile = "testCA.ks";
        String keyPass = "j4ops";    

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load (null, keyPass.toCharArray());   
        ks.setCertificateEntry(certCA.getIssuerX500Principal().getName(), certCA);      
        
        // set tsa certificate
        FileInputStream fis = null;
        try {
            fis = new FileInputStream ("src/test/resources/edelwebTSA.cer");
            X509Certificate tsaCert = X509Util.toX509Certificate(fis, "BC");
            ks.setCertificateEntry("tsa1", tsaCert);            
        }
        finally {
            try {
                if (fis != null) {
                    fis.close();
                    fis = null;
                }
            }
            catch (Exception ex) {}
        }   
        try {
            fis = new FileInputStream ("src/test/resources/sziksziTSA.cer");
            X509Certificate tsaCert = X509Util.toX509Certificate(fis, "BC");
            ks.setCertificateEntry("tsa2", tsaCert);            
        }
        finally {
            try {
                if (fis != null) {
                    fis.close();
                    fis = null;
                }
            }
            catch (Exception ex) {}
        }         
        
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(keyFile);
            ks.store (out, keyPass.toCharArray());
            out.flush();
        }
        finally {
            try {
                if (out != null) {
                    out.close();
                    out = null;
                }
            }
            catch (Exception ex) {}
        }           
        
    }
    
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024, new SecureRandom());
        return kpGen.generateKeyPair();
    }    
    
    public static void testGeneratePKCS12 () throws Exception {

		Date firstDate = new Date();
		Date lastDate = new Date(firstDate.getTime() + VALIDITY*24*60*60*1000L); 
        
        
        KeyPair keyCA = generateRSAKeyPair();
        BigInteger sn = new BigInteger  ("1");
        X509Certificate certCA = generateV3Certificate("CN=Test CA Certificate", sn, firstDate, lastDate, 
                                                        keyCA, KeyUsage.keyEncipherment, true);
        certCA.checkValidity(new Date());
        certCA.verify(certCA.getPublicKey());

        String keyFile = "j4ops.p12";
        String keyPass = "sign";    

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load (null, keyPass.toCharArray());   
        ks.setKeyEntry("ca", keyCA.getPrivate(), keyPass.toCharArray(), new X509Certificate []{certCA});
                
        // generate user certificate
        KeyPair keyUser = generateRSAKeyPair();
        sn = new BigInteger  ("2");
        X509Certificate certUser = generateV3Certificate("CN=Test User Certificate", sn, firstDate, lastDate, 
                                                        keyUser, KeyUsage.digitalSignature | KeyUsage.nonRepudiation, false);        

        // sign user certificate with ca private key
        certUser = signCertificate (certUser, certCA, keyCA.getPrivate(), SIG_ALG_NAME, false);
        ks.setKeyEntry("sign", keyUser.getPrivate(), keyPass.toCharArray(), new X509Certificate []{certUser});
        
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(keyFile);
            ks.store (out, keyPass.toCharArray());
            out.flush();
        }
        finally {
            try {
                if (out != null) {
                    out.close();
                    out = null;
                }
            }
            catch (Exception ex) {}
        }   
        
        createKeyStoreCA (certCA);        
    }


    @Override
    protected void setUp() {
        //DOMConfigurator.configure("log4j.xml");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());        

    }        

    @Override
    public void tearDown() {
    }


    public static void main(String[] args) throws Exception {
        TestRunner.run(GeneratePKCS12.class);
    }

}
