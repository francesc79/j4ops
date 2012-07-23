package it.j4ops.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import org.apache.log4j.Logger;

public class NativeLibLoader {
	private static Logger logger = Logger.getLogger(NativeLibLoader.class);
	private static final int OS_UNSUPPORTED = -1;
	private static final int OS_LINUX = 1;
	private static final int OS_WINDOWS = 2;
	private static final int OS_WINDOWS_CE = 3;
	private static final int OS_MAC_OS_X = 4;
	private static HashSet lstLibraryLoaded = new HashSet ();
	
	
	private static int getOS() {
		int os = 0;
		String sysName = System.getProperty("os.name");
		if (sysName == null) {
			logger.fatal("Native Library not available on unknown platform");
			os = OS_UNSUPPORTED;
		} else {
			sysName = sysName.toLowerCase();
			if (sysName.indexOf("windows") != -1) {
				if (sysName.indexOf("ce") != -1) {
					os = OS_WINDOWS_CE;
				} else {
					os = OS_WINDOWS;
				}
			} else if (sysName.indexOf("mac os x") != -1) {
				os = OS_MAC_OS_X;
			} else if (sysName.indexOf("linux") != -1) {
				os = OS_LINUX;
			} else {
				logger.fatal("Native Library not available on platform " + sysName);
				os = OS_UNSUPPORTED;
			}
		}
		return os;
	}	
	
	private static boolean copy2File(InputStream is, File fd) {
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(fd);
			byte b[] = new byte[1000];
			int len;
			while ((len = is.read(b)) >= 0) {
				fos.write(b, 0, len);
			}
			return true;
		} catch (Exception e) {
			logger.debug("Error on create temp file " + fd.getAbsolutePath(), e);
			return false;
		} finally {
			if (fos != null) {
				try {
					fos.close();
				} catch (IOException ignore) {
					fos = null;
				}
			}
		}
	}
	
	
	public static void loadLib (String path, final String name) throws Exception {
		InputStream in = null;
		String fileName = name;
			
		try {
			if (lstLibraryLoaded.contains(name)) {
				return;
			}
			
			String sysName = System.getProperty("os.name");
			String sysArch = System.getProperty("os.arch");
			if (sysArch != null) {
				sysArch = sysArch.toLowerCase();
			} else {
				sysArch = "";
			}

			switch (getOS()) {
                case OS_WINDOWS_CE:
                    fileName += "_ce.dll";
                    break;
                case OS_WINDOWS:
                    if ((sysArch.indexOf("amd64") != -1) || (sysArch.indexOf("x86_64") != -1)) {
                        fileName += "_x64";
                    }
                    fileName +=  ".dll";
                    break;
                case OS_MAC_OS_X:
                    fileName += ".jnilib";
                    break;
                case OS_LINUX:
                    if ((sysArch.indexOf("i386") != -1) || (sysArch.length() == 0)) {
                        // regular Intel
                    } else if ((sysArch.indexOf("amd64") != -1) || (sysArch.indexOf("x86_64") != -1)) {
                        fileName += "_x64";
                    } else if ((sysArch.indexOf("x86") != -1)) {
                        // regular Intel under IBM J9
                    } else {
                        // Any other system
                        fileName += "_" + sysArch;
                    }
                    fileName += ".so";
                    break;

                case OS_UNSUPPORTED:
                    throw new Exception("Native Library " + name + " not available on [" + sysName + "] platform");

                default:
                    throw new Exception ("Native Library " + name + " not available on platform " + sysName);
			}			
						
			in = NativeLibLoader.class.getResourceAsStream(fileName);
			if (in == null) {
				throw new Exception ("Resource " + fileName + " not found");
			}

			File fileOut = new File(System.getProperty("java.io.tmpdir")
					+ System.getProperty("file.separator") + path + fileName);
			if (fileOut.exists()) {
				fileOut.delete();
			}

			logger.info("write lib into: " + fileOut.getAbsolutePath());
			copy2File (in, fileOut);			

			in.close();
			in = null;		

			System.load (fileOut.toString());

			logger.info("Library " + fileOut.getAbsolutePath() + " loaded successful");	

			lstLibraryLoaded.add(name);
		} catch (Exception e) {
			logger.fatal(e.toString(), e);	
			throw new Exception("Error on loading library " + name, e);
		}
		finally {
			try {
				if (in != null) {
					in.close();
					in = null;
				}
			}
			catch (Exception ex) {}		
		}
	}
}
