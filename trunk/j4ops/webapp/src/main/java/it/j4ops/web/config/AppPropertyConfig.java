package it.j4ops.web.config;

import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.core.io.Resource;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Properties;


public class AppPropertyConfig extends PropertyPlaceholderConfigurer {
    private Resource persistLocation = null;


    public void setPersistLocation(Resource persistLocation) {
        this.persistLocation = persistLocation;
        setLocation(persistLocation);
    }

    @SuppressWarnings("unchecked")
    public void persistProperties (Properties properties) throws Exception {
        this.setProperties(properties);
        OutputStream os = null;
        try {
            if (logger.isDebugEnabled()) {
                Enumeration<String> enumer = (Enumeration<String>)properties.propertyNames();
                while (enumer.hasMoreElements()) {
                    String key = enumer.nextElement();
                    logger.debug(String.format("updating property %s val %s", key, properties.getProperty(key)));
                }

                logger.debug("save file:" + persistLocation.getFile());
            }

            os = new FileOutputStream (persistLocation.getFile());
            properties.store(os, "");
        }
        catch (Exception ex) {
            logger.fatal(ex.toString(), ex);
            throw ex;
        }
        finally {
            try {
                if (os != null) {
                    os.close();
                }
            }
            catch (Exception ex) {}
        }
    }
}
