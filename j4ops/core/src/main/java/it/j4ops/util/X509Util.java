/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.util;

import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author fzanutto
 */
public class X509Util {
    private static Logger logger = LoggerFactory.getLogger(X509Util.class);
    
    public static String toString (X509PublicKeyCertificate certificate, String provider) {
        String certificateString = null;
        if (certificate != null) {
            try {
                X509Certificate correspondingCertificate = toX509Certificate(certificate.getValue().getByteArrayValue(), provider);
                certificateString = correspondingCertificate.toString();
            } catch (Exception ex) {
                logger.error(ex.getMessage(), ex);
                certificateString = certificate.toString();
            }
        }
        return certificateString;
    }

    public static X509Certificate toX509Certificate (InputStream is, String provider) throws CertificateException, IOException, NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        ByteArrayInputStream bais = new ByteArrayInputStream(DERUtil.streamToByteArray(is));
        X509Certificate x509Cert = null;
        try {
            x509Cert = (X509Certificate)cf.generateCertificate (bais);
        }
        finally {
            bais.close();        
        }
        return x509Cert;
    }     
    
    public static X509Certificate toX509Certificate (byte[] encodedCertificate, String provider) throws CertificateException, IOException, NoSuchProviderException {
        ByteArrayInputStream bais = new ByteArrayInputStream(encodedCertificate);
        X509Certificate x509Cert = null;
        try {
            x509Cert = toX509Certificate (bais, provider);
        }
        finally {
            bais.close();        
        }
        return x509Cert;
    }    
    
    public static String getDescrKeyUsage (X509Certificate certificate) {
        StringBuilder sb = new StringBuilder();
        String descrKeyUsage [] = {"digitalSignature", "nonRepudiation",
                                   "keyEncipherment",  "dataEncipherment",
                                   "keyAgreement",     "keyCertSign",
                                   "cRLSign",          "encipherOnly",
                                   "decipherOnly"};

        boolean []keyUsage = certificate.getKeyUsage();
       
        if (keyUsage != null) {
            for (int index = 0; index < keyUsage.length; index ++) {
                if (keyUsage[index]) {
                    if (sb.length() > 0) {
                        sb.append(",");
                    }
                    if (index > descrKeyUsage.length) {
                        sb.append("unknow");
                    }
                    else {
                        sb.append(descrKeyUsage[index]);
                    }
                }
            }
        }

        return sb.toString();
    }

    public static Set<X509Certificate> loadKeyStore (String keyFile, String keyPass) throws Exception {
        return loadKeyStore (keyFile, keyPass, "JKS");
    }    
    
    public static Set<X509Certificate> loadKeyStore (String keyFile, String keyPass, String keyStoreType) throws Exception {
        Set<X509Certificate> lstCerts = new HashSet<X509Certificate> ();
        KeyStore ks = KeyStore.getInstance(keyStoreType);
        InputStream is = null;
        try {
            if (new File (keyFile).exists()) {
                is = new FileInputStream(keyFile);
            }
            else {
                is = X509Util.class.getClassLoader().getResourceAsStream (keyFile);
            }
            if (is == null) {             
                throw new Exception ("resource " + keyFile + " not found");
            }
            ks.load (is, keyPass.toCharArray());
            
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement(); 
                Certificate []certs = ks.getCertificateChain(alias);
                if (certs != null) {
                    for (Certificate cert : certs) {
                        if (cert != null && cert instanceof X509Certificate) { 
                            if (!lstCerts.contains((X509Certificate)cert)) {
                                lstCerts.add((X509Certificate)cert);
                            }
                        }                         
                    }     
                }
                Certificate cert = ks.getCertificate(alias);
                if (cert != null && cert instanceof X509Certificate) {                       
                    if (!lstCerts.contains((X509Certificate)cert)) {
                        lstCerts.add((X509Certificate)cert);
                    }
                } 
            }
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
        
        return lstCerts;
    }

    public static X509Certificate validateChain (X509Certificate cert,
                                                 Set<X509Certificate> additionalCerts, 
                                                 String provider) throws Exception {   
        return validateChain (cert, additionalCerts, null, provider);
    }    
    
    public static X509Certificate validateChain (X509Certificate cert,
                                                 Set<X509Certificate> additionalCerts, 
                                                 PKIXCertPathChecker pkixCertPathChecker,
                                                 String provider) throws Exception {                
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", provider); 
        CertPath path = cf.generateCertPath(Arrays.asList(new java.security.cert.Certificate[] {cert}));        
        
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        Set<X509Certificate> intermediateCerts = new HashSet<X509Certificate>();
        for (X509Certificate additionalCert : additionalCerts) {
            if (isSelfSigned(additionalCert)) {
                trustAnchors.add(new TrustAnchor(additionalCert, null));
            } else {
                intermediateCerts.add(additionalCert);
            }
        }

        PKIXParameters pkixParams = new PKIXParameters(trustAnchors);
        pkixParams.setRevocationEnabled(false); 
        if (pkixCertPathChecker != null) {
            pkixParams.addCertPathChecker(pkixCertPathChecker);
        }

        // Specify a list of intermediate certificates
        CertStore intermediateCertStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(intermediateCerts), provider);
        pkixParams.addCertStore(intermediateCertStore);               
            
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)validator.validate(path, pkixParams);        
        return result.getTrustAnchor().getTrustedCert();
    }
    
    
	/**
	 * Attempts to build a certification chain for given certificate and to verify
	 * it. Relies on a set of root CA certificates and intermediate certificates
	 * that will be used for building the certification chain. The verification
	 * process assumes that all self-signed certificates in the set are trusted
	 * root CA certificates and all other certificates in the set are intermediate
	 * certificates.
	 *
	 * @param cert - certificate for validation
	 * @param additionalCerts - set of trusted root CA certificates that will be
	 * 		used as "trust anchors" and intermediate CA certificates that will be
	 * 		used as part of the certification chain. All self-signed certificates
	 * 		are considered to be trusted root CA certificates. All the rest are
	 * 		considered to be intermediate CA certificates.
	 * @return the certification chain (if verification is successful)
	 * @throws Exception - if the certification is not
	 * 		successful (e.g. certification path cannot be built or some
	 * 		certificate in the chain is expired or CRL checks are failed)
	 */    
    public static List<X509Certificate> buildAndValidateChain (X509Certificate cert,
                                                               Set<X509Certificate> additionalCerts, 
                                                               String provider) throws Exception {
        List<X509Certificate> lstChain = new ArrayList<X509Certificate>();

        // Check for self-signed certificate
        if (isSelfSigned(cert)) {
            throw new Exception("The certificate is self-signed.");
        }

        // Prepare a set of intermediate certificates
        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        Set<X509Certificate> intermediateCerts = new HashSet<X509Certificate>();
        for (X509Certificate additionalCert : additionalCerts) {
            if (isSelfSigned(additionalCert)) {
                trustAnchors.add(new TrustAnchor(additionalCert, null));
            } else {
                intermediateCerts.add(additionalCert);
            }
        }
        // add certificate to intermediate certs
        intermediateCerts.add(cert);

        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);    

        // Specify a list of intermediate certificates
        CertStore intermediateCertStore = CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(intermediateCerts), provider);
        pkixParams.addCertStore(intermediateCertStore);

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", provider);              
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(pkixParams);

        // create chain
        lstChain.add(result.getTrustAnchor().getTrustedCert());
        for (java.security.cert.Certificate c : result.getCertPath().getCertificates()) {
            if (c instanceof X509Certificate) {
                lstChain.add((X509Certificate)c);
            }
            else {
                lstChain.add(X509Util.toX509Certificate(c.getEncoded(), provider));
            }
        }                        
      
        return lstChain;
    }
    
    

	/**
	 * Checks whether given X.509 certificate is self-signed.
	 */
	private static boolean isSelfSigned(X509Certificate cert)
			throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		try {
			// Try to verify certificate signature with its own public key
			PublicKey key = cert.getPublicKey();
			cert.verify(key);
			return true;
		} catch (SignatureException sigEx) {
			// Invalid signature --> not self-signed
			return false;
		} catch (InvalidKeyException keyEx) {
			// Invalid key --> not self-signed
			return false;
		}
	}    
}
