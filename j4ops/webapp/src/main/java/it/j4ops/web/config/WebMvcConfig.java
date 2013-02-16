package it.j4ops.web.config;

import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.web.servlet.mvc.WebContentInterceptor;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.UrlBasedViewResolver;
import org.springframework.web.servlet.view.tiles2.TilesConfigurer;
import org.springframework.web.servlet.view.tiles2.TilesView;

import java.util.Locale;
import java.util.Properties;

/**
 *
 * @author zanutto
 */
@Configuration
@EnableWebMvc
@ComponentScan(basePackages = { "it.j4ops.web" })
public class WebMvcConfig extends WebMvcConfigurerAdapter {
    public static final String DIR_DOCUMENTS = "/documents/";
    public static final String DIR_VERIFIED = "/verified/";

    private static final long MAX_FILE_UPLOAD_SIZE = 1024 * 1024 * 5; //5 Mb file limit
    private static final int FILE_SIZE_THRESHOLD = 1024 * 1024; // After 1Mb start writing files to disk

    @Override
    public void addResourceHandlers(final ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/resources/**").addResourceLocations("/resources/");
    }

    @Override
    public void configureDefaultServletHandling(final DefaultServletHandlerConfigurer configurer) {
        configurer.enable();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
        registry.addInterceptor(webContentInterceptor ());
    }

    //-- Start Locale Support (I18N)

    @Bean
    public HandlerInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
        localeChangeInterceptor.setParamName("lang");
        return localeChangeInterceptor;
    }

    @Bean
    public LocaleResolver localeResolver() {
        SessionLocaleResolver localeResolver = new SessionLocaleResolver();
        localeResolver.setDefaultLocale(Locale.ENGLISH);
        return localeResolver;
    }

    @Bean
    public MessageSource messageSource() {
        ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
        messageSource.setBasename("/WEB-INF/messages/messages");
        messageSource.setUseCodeAsDefaultMessage(true);
        return messageSource;
    }

    // Session no cache
    @Bean
    public WebContentInterceptor webContentInterceptor () {
        WebContentInterceptor webContentInterceptor = new WebContentInterceptor ();
        webContentInterceptor.setUseCacheControlHeader(true);
        webContentInterceptor.setUseCacheControlNoStore(true);
        webContentInterceptor.setUseExpiresHeader(true);
        webContentInterceptor.setCacheSeconds(-1);

        Properties cacheMappings = new Properties();
        cacheMappings.setProperty("/index.htm", "0");
        webContentInterceptor.setCacheMappings(cacheMappings);
        return webContentInterceptor;
    }

    // ViewResolver
    
    @Bean
    public TilesConfigurer tilesConfigurer() {
        TilesConfigurer tilesConfigurer = new TilesConfigurer();
        tilesConfigurer.setDefinitions(new String []{"/WEB-INF/tiles.xml"});        
        return tilesConfigurer;
    }

    @Bean
    public UrlBasedViewResolver tilesViewResolver() {
        UrlBasedViewResolver urlBasedViewResolver = new UrlBasedViewResolver ();
        urlBasedViewResolver.setViewClass(TilesView.class);
        urlBasedViewResolver.setOrder(0);
        return urlBasedViewResolver;
    }    

    @Bean
    public InternalResourceViewResolver internalResourceViewResolver () {
        InternalResourceViewResolver internalResourceViewResolver = new InternalResourceViewResolver ();
        internalResourceViewResolver.setPrefix("/WEB-INF/views/");
        internalResourceViewResolver.setSuffix(".jsp");
        internalResourceViewResolver.setOrder(1);
        return internalResourceViewResolver;
    }

    // Multipart Resolver

    @Bean
    public MultipartResolver multipartResolver () {
        CommonsMultipartResolver multipartResolver = new CommonsMultipartResolver();
        multipartResolver.setMaxInMemorySize(FILE_SIZE_THRESHOLD);
        multipartResolver.setMaxUploadSize(MAX_FILE_UPLOAD_SIZE);
        return multipartResolver;
    }

    @Bean
    public AppPropertyConfig getAppPropertyConfig () {
        AppPropertyConfig appPropertyConfig = new AppPropertyConfig();
        appPropertyConfig.setPersistLocation(new ClassPathResource("j4ops.properties"));
        return appPropertyConfig;
    }
}
