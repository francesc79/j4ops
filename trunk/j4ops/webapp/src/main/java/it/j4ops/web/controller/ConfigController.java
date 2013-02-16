package it.j4ops.web.controller;

import it.j4ops.web.config.AppPropertyConfig;
import it.j4ops.web.model.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Properties;

@Controller
public class ConfigController implements MessageSourceAware {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private MessageSource messageSource;

    @Autowired
    private AppPropertyConfig appPropertyConfig;

    @Autowired
    private Configuration config;

    @ModelAttribute("config")
    public Configuration getConfiguration() {
        return config;
    }

    @RequestMapping(value = "/config.htm", method = RequestMethod.GET)
    public String config () throws Exception {
        return "config";
    }

    @RequestMapping(value = "/config/save.htm", method = RequestMethod.POST)
    public String save (HttpServletRequest request, @Validated Configuration config, BindingResult result, RedirectAttributes redirectAttributes) throws Exception {

        if (result.hasErrors()) {
            logger.error("error on save config:" + result.getAllErrors().toString());
            return "config";
        }
        else {
            Properties prop = config.getProperties();
            this.config.updateProperties(prop);
            appPropertyConfig.persistProperties(prop);
            redirectAttributes.addFlashAttribute("message", messageSource.getMessage("config.success.message", null, request.getLocale()));
        }

        return "redirect:/config.htm";
    }


    @Override
    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
}
