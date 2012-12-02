/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.util.io.Streams;

/**
 *
 * @author fzanutto
 */
public class DERUtil {
    public static byte[] toByteArray(DEREncodable derEncObject) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dout = new ASN1OutputStream(bOut);
        dout.writeObject(derEncObject);
        dout.close();
        return bOut.toByteArray();
    } 

    public static DERObject readDERObject(byte[] ab) throws IOException{
        ASN1InputStream in = getASN1InputStream(ab);
        return in.readObject();
    }  

    private static ASN1InputStream getASN1InputStream(byte[] ab) {
        ByteArrayInputStream bais = new ByteArrayInputStream(ab);
        return new ASN1InputStream(bais);
    }   

    public static byte[] streamToByteArray(InputStream stream) throws IOException {
        if (stream == null) {
            return null;
        } else {
            return Streams.readAll(stream);
        }
    } 

    public static byte [] getHash (InputStream is, String digestAlgOID, String securityProvider)    
                            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CMSException {
        MessageDigest md = MessageDigest.getInstance(digestAlgOID, securityProvider);
        
        byte bb[] = new byte[1024];
        int n = 0;
        while ((n = is.read(bb)) > 0)
            md.update(bb, 0, n);

        return md.digest();        
    }      
    
    public static byte [] getHash (byte [] content, String digestAlgOID, String securityProvider)    
                            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CMSException {
        MessageDigest md = MessageDigest.getInstance(digestAlgOID, securityProvider);
        md.update(content);
        return md.digest();        
    }        
       
    public static byte [] getHash (CMSProcessable content, String digestAlgOID, String securityProvider) 
                            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CMSException {
        final MessageDigest dig = MessageDigest.getInstance(digestAlgOID, securityProvider);        
        content.write(new OutputStream() {

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                dig.update(b, off, len);
            }

            @Override
            public void write(int b) throws IOException {
                dig.update((byte) b);
            }        
        });
        return dig.digest();    
    }       
}
