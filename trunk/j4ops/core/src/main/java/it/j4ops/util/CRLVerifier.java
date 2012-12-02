/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.util;

import it.j4ops.util.X509Util;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.X509Extension;

/**
 * Class that verifies CRLs for given X509 certificate. Extracts the CRL
 * distribution points from the certificate (if available) and checks the
 * certificate revocation status against the CRLs coming from the
 * distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
 *
 * @author Svetlin Nakov
 */
public class CRLVerifier {
    private static Logger logger = LoggerFactory.getLogger(CRLVerifier.class);
    
	/**
	 * Extracts the CRL distribution points from the certificate (if available)
	 * and checks the certificate revocation status against the CRLs coming from
	 * the distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
	 *
	 * @param cert the certificate to be checked for revocation
	 * @throws Exception if the certificate is revoked
	 */
	public static List<X509CRL> verifyCertificateCRLs(X509Certificate cert) throws Exception {
        List<X509CRL> lstX509CRL = new ArrayList<X509CRL>();        
		try {
			List<String> crlDistPoints = getCrlDistributionPoints(cert);
			for (String crlDP : crlDistPoints) {
                logger.debug("crl dist point:" + crlDP);
				X509CRL crl = downloadCRL(crlDP);
				if (crl.isRevoked(cert)) {
					throw new Exception("The certificate is revoked by CRL: " + crlDP);
				}
                lstX509CRL.add(crl);
			}
		} catch (Exception ex) {
            throw new Exception("Can not verify CRL for certificate: " + cert.getSubjectX500Principal(), ex);
		}
        
        return lstX509CRL;
	}

	/**
	 * Downloads CRL from given URL. Supports http, https, ftp and ldap based URLs.
	 */
	private static X509CRL downloadCRL(String crlURL) throws Exception {
        X509CRL crl = null;
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
				|| crlURL.startsWith("ftp://")) {
			crl = downloadCRLFromWeb(crlURL);
		} else if (crlURL.startsWith("ldap://")) {
			crl = downloadCRLFromLDAP(crlURL);
		} else {
			throw new Exception("Can not download CRL from certificate " +
					"distribution point: " + crlURL);
		}
        return crl;
	}

	/**
	 * Downloads a CRL from given LDAP url, e.g.
	 * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
	 */
	private static X509CRL downloadCRLFromLDAP(String ldapURL) throws Exception {
		Hashtable<String , String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext(env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[])aval.get();
        if ((val == null) || (val.length == 0)) {
        	throw new Exception("Can not download CRL from: " + ldapURL);
        } else {
        	InputStream inStream = new ByteArrayInputStream(val);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
        	return (X509CRL)cf.generateCRL(inStream);
        }
	}

	/**
	 * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
	 * http://crl.infonotary.com/crl/identity-ca.crl
	 */
	private static X509CRL downloadCRLFromWeb(String crlURL)
			throws IOException, CertificateException,
			CRLException {
		URL url = new URL(crlURL);
		InputStream crlStream = url.openStream();
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509CRL) cf.generateCRL(crlStream);
		} finally {
			crlStream.close();
		}
	}

	/**
	 * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
	 * extension in a X.509 certificate. If CRL distribution point extension is
	 * unavailable, returns an empty list.
	 */
	public static List<String> getCrlDistributionPoints(X509Certificate cert) throws CertificateParsingException, IOException {
		byte[] crldpExt = cert.getExtensionValue(X509Extension.cRLDistributionPoints.getId());
		if (crldpExt == null) {
			return Collections.EMPTY_LIST;
		}
		ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crldpExt));
		DERObject derObjCrlDP = oAsnInStream.readObject();
		DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
		byte[] crldpExtOctets = dosCrlDP.getOctets();
		ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
		DERObject derObj2 = oAsnInStream2.readObject();
		CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
		List<String> crlUrls = new ArrayList<String>();
		for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null) {
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                    // Look for an URI
                    for (GeneralName genName : genNames) {
                        if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(genName.getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
		}
		return crlUrls;
	}

}
