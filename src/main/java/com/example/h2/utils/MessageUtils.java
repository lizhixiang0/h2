package com.example.h2.utils;
import com.example.h2.spring.SpringContextHolder;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;

import javax.servlet.http.HttpServletRequest;
import java.util.Locale;

/**
 * The type Message utils.
 * @author admin
 */
public class MessageUtils {

    /**
     * The constant logger.
     */
    protected static Logger logger = LoggerFactory.getLogger(MessageUtils.class);

    private MessageUtils() {
    }

    private static MessageSource getMessageSource() {
        return  SpringContextHolder.getBean(MessageSource.class);
    }


    /**
     * Gets locale message.
     *
     * @param code the code
     * @param args the args
     * @return the locale message
     */
    public static String getLocaleMessage(String code, Object... args) {
        LocaleResolver localLocaleResolver = (LocaleResolver) SpringContextHolder.getBean(LocaleResolver.class);
        //这一步，找到请求地的那啥
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        Locale localLocale = localLocaleResolver.resolveLocale(request);
        return getLocaleMessage(code, localLocale, args);
    }

    /**
     * Gets locale message.
     *
     * @param code   the code
     * @param locale the locale
     * @param args   the args
     * @return the locale message
     */
    public static String getLocaleMessage(String code, Locale locale, Object... args) {
        if (StringUtils.isBlank(code)) {
            return code;
        }
        try {
            return getMessageSource().getMessage(code, args, locale);
        } catch (NoSuchMessageException ex) {
            logger.warn("Error when getLocaleMessage for code: {}", code);
            return code;
        }
    }

    /**
     * Gets english message.
     *
     * @param code the code
     * @param args the args
     * @return the english message
     */
    public static String getEnglishMessage(String code, Object... args) {
        if (getMessageSource() != null) {
            try {
                return getMessageSource().getMessage(code, args, Locale.ENGLISH);
            } catch (NoSuchMessageException ex) {
                logger.warn("Error when getEnglishMessage for code: {}", code);
                return code;
            }
        }
        return code;
    }

}
