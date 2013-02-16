/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package it.j4ops.web.util;

import com.lowagie.text.pdf.*;
import com.lowagie.text.*;

import java.awt.*;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author zanutto
 */
public class PDFUtil {
    public static void changePDF (InputStream is, OutputStream os, String text) throws Exception {
        PdfReader pdfReader = new PdfReader(is);        
        PdfStamper pdfStamper = new PdfStamper(pdfReader, os);
        for (int index = 1; index <= pdfReader.getNumberOfPages(); index ++){
            PdfContentByte underContent = pdfStamper.getUnderContent(index);
            underContent.beginText();
            BaseFont bf = BaseFont.createFont(BaseFont.TIMES_BOLD,BaseFont.WINANSI,BaseFont.EMBEDDED);
            underContent.setFontAndSize(bf, 10);
            underContent.setColorFill(Color.BLACK);
            underContent.showTextAligned(Element.ALIGN_TOP, text, 10, 30, 0);
            underContent.endText();
        }
        pdfStamper.close();            
    }
}
