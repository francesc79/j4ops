package it.j4ops.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NativeLibLoader {
	private static Logger logger = LoggerFactory.getLogger(NativeLibLoader.class);
	public static final int OS_UNSUPPORTED = -1;
	public static final int OS_LINUX = 1;
	public static final int OS_WINDOWS = 2;
	public static final int OS_WINDOWS_CE = 3;
	public static final int OS_MAC_OS_X = 4;
	private static HashSet lstLibraryLoaded = new HashSet ();
	
	
	public static int getOS() {
		int os = 0;
		String sysName = System.getProperty("os.name");
		if (sysName == null) {
			logger.error("Native Library not available on unknown platform");
			os = OS_UNSUPPORTED;
		} else {
			sysName = sysName.toLowerCase();
			if (sysName.contains("windows")) {
				if (sysName.contains("ce")) {
					os = OS_WINDOWS_CE;
				} else {
					os = OS_WINDOWS;
				}
			} else if (sysName.contains("mac os x")) {
				os = OS_MAC_OS_X;
			} else if (sysName.contains("linux")) {
				os = OS_LINUX;
			} else {
				logger.error("Native Library not available on platform " + sysName);
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
	
    public static void setLibraryPath(String path) throws Exception {
        System.setProperty("java.library.path", path);

        //set sys_paths to null
        final Field sysPathsField = ClassLoader.class.getDeclaredField("sys_paths");
        sysPathsField.setAccessible(true);
        sysPathsField.set(null, null);
    }    
    
    public static void addLibraryPath(String pathToAdd) throws Exception{
        final Field usrPathsField = ClassLoader.class.getDeclaredField("usr_paths");
        usrPathsField.setAccessible(true);

        //get array of paths
        final String[] paths = (String[])usrPathsField.get(null);

        //check if the path to add is already present
        for (String path : paths) {
            if (path.equals (pathToAdd)) {
                return;
            }
        }

        //add the new path
        final String[] newPaths = Arrays.copyOf(paths, paths.length + 1);
        newPaths[newPaths.length-1] = pathToAdd;
        usrPathsField.set(null, newPaths);       
    }   
    
    public static File extractLib (String path, final String name) throws Exception {
		InputStream in = null;
		String fileName = name;
        File fileOut = null;
			
		try {
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
                    if ((sysArch.contains("amd64")) || (sysArch.contains("x86_64"))) {
                        fileName += "_x64";
                    }
                    fileName +=  ".dll";
                    break;
                case OS_MAC_OS_X:
                    fileName += ".jnilib";
                    break;
                case OS_LINUX:
                    if ((sysArch.contains("i386")) || (sysArch.length() == 0)) {
                        // regular Intel
                    } else if ((sysArch.contains("amd64")) || (sysArch.contains("x86_64"))) {
                        fileName += "_x64";
                    } else if ((sysArch.contains("x86"))) {
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

			fileOut = new File(System.getProperty("java.io.tmpdir") + System.getProperty("file.separator") + path + fileName);
			if (fileOut.exists()) {
				fileOut.delete();
			}

			logger.info("write lib into: " + fileOut.getAbsolutePath());
			copy2File (in, fileOut);			

		} catch (Exception e) {
			logger.error(e.toString(), e);
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
        
        return fileOut;        
    } 
	
	public static void loadLib (String path, final String name) throws Exception {
			
		try {
			if (lstLibraryLoaded.contains(name)) {
				return;
			}
			
			File fileOut = extractLib (path, name);		            
			System.load (fileOut.toString());

			logger.info("Library " + fileOut.getAbsolutePath() + " loaded successful");	

			lstLibraryLoaded.add(name);
		} catch (Exception e) {
			logger.error(e.toString(), e);
			throw new Exception("Error on loading library " + name, e);
		}

	}
}
