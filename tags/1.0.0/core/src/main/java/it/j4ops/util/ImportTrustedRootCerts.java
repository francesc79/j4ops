/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.util;

import it.j4ops.util.X509Util;
import it.j4ops.verify.CmsVerify;
import it.j4ops.verify.bean.VerifyInfo;
import java.io.*;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;

/**
 *
 * @author fzanutto
 */
public class ImportTrustedRootCerts {
    private Logger logger = Logger.getLogger(this.getClass());    
    private KeyStore ks = null;
    private String keyFile = null;
    private String keyPass = null;
    
    public ImportTrustedRootCerts (String keyFile, String keyPass, String provider) throws Exception {
        this.keyFile = keyFile;
        this.keyPass = keyPass;
        ks = KeyStore.getInstance("JKS", provider);
        ks.load (null, keyPass.toCharArray());          
    }
    
    public void close () throws Exception {
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
    
    private InputStream loadArchive (String nameArchive) throws Exception {
        FileInputStream fis = null;
        ByteArrayOutputStream baos = null;
        
        logger.debug(String.format("verifing %s", nameArchive));
        Properties prop = new Properties ();      
        CmsVerify p7xVerify = new CmsVerify (prop);        
        try {
            fis = new FileInputStream (nameArchive);
            baos = new ByteArrayOutputStream ();
            VerifyInfo vi = p7xVerify.verify(fis, null, baos);            
        }
        finally {
            try {
                if (fis != null) {
                    fis.close();
                    fis = null;
                }
            }
            catch (IOException ex) {}           
        } 
        
        return new ByteArrayInputStream(baos.toByteArray());
    }
    
    private void parsingArchive (InputStream is, String provider) throws Exception {
        ZipInputStream zis = new ZipInputStream(new BufferedInputStream(is));
        ZipEntry entry;

        while ((entry = zis.getNextEntry()) != null) {
            if (entry.isDirectory() == true) {
                continue;
            }
            if (entry.getName().endsWith(".rtf")) {
                continue;
            }

            //logger.debug (String.format("File name: %s; size: %d; compressed size: %d", 
            //                    entry.getName(), entry.getSize(), entry.getCompressedSize())); 
            
            // add certificate
            addCertificate (zis, entry, provider);
        }

        zis.close();
        is.close();
    }
    
    private boolean checkCertificateExists (X509Certificate x509Cert) throws Exception {

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement(); 
            Certificate []certs = ks.getCertificateChain(alias);
            if (certs != null) {
                for (Certificate cert : certs) {
                    if (x509Cert.equals(cert)) {
                        return true;
                    }
                }     
            }
            Certificate cert = ks.getCertificate(alias);
            if (cert != null) {
                if (x509Cert.equals(cert)) {
                    return true;
                }      
            }
        }
        
        return false;
    }
    
    private void addCertificate (ZipInputStream zis, ZipEntry entry, String provider) throws Exception {
        byte[] buffer = new byte[2048];  
        int size;   
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        BufferedOutputStream bos = null;
        try {
             bos = new BufferedOutputStream(baos, buffer.length);
            while ((size = zis.read(buffer, 0, buffer.length)) != -1) {
                bos.write(buffer, 0, size);
            }
            bos.flush();
        }
        finally {
            try {
                if (bos != null) {
                    bos.close(); 
                    bos = null;
                }
            }
            catch (Exception ex) {}
        }
        
        X509Certificate x509Cert = X509Util.toX509Certificate(baos.toByteArray(), provider);
        if (checkCertificateExists(x509Cert) == false) {
            logger.debug(String.format("adding certificate %s", entry.getName()));
            ks.setCertificateEntry(entry.getName(), x509Cert);
        }
        else {
            logger.debug(String.format("certificate %s alredy added", entry.getName()));
        }
    }
    

    public static void main(String[] args) throws Exception {
        DOMConfigurator.configure("log4j.xml");
        String provider = "SUN";
        ImportTrustedRootCerts imp = new ImportTrustedRootCerts ("certs.ks", "j4ops", provider);
        imp.parsingArchive(imp.loadArchive("./src/main/resources/LISTACER_20120209.zip.p7m"), provider);
        imp.close();
    }    
}
