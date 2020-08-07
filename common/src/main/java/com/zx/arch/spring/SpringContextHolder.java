package com.zx.arch.spring;//


import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.EmbeddedValueResolverAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.util.StringValueResolver;

import java.util.Map;

@Service
@Lazy(false)
public class SpringContextHolder implements ApplicationContextAware, DisposableBean, EmbeddedValueResolverAware, EnvironmentAware {
    private static ApplicationContext applicationContext = null;
    private static StringValueResolver stringValueResolver = null;
    private static Environment environment = null;
    private static Logger logger = LoggerFactory.getLogger(SpringContextHolder.class);

    public SpringContextHolder() {
    }

    public static ApplicationContext getApplicationContext() {
        assertContextInjected();
        return applicationContext;
    }


    public static <T> T getBean(Class<T> requiredType) {
        assertContextInjected();
        return applicationContext.getBean(requiredType);
    }

    public static <T> T getBean(String name, Class<T> requiredType) {
        assertContextInjected();
        return applicationContext.getBean(name, requiredType);
    }

    public static <T> Map<String, T> getBeansOfType(Class<T> requiredType) {
        assertContextInjected();
        return applicationContext.getBeansOfType(requiredType);
    }

    public static void clearHolder() {
        if (logger.isDebugEnabled()) {
            logger.debug("Clearing ApplicationContext from SpringContextHolder:" + applicationContext);
        }

        applicationContext = null;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        logger.debug("Inject ApplicationContext into SpringContextHolder:{}", applicationContext);
        if (SpringContextHolder.applicationContext != null) {
            logger.info("ApplicationContext is override in SpringContextHolder, original ApplicationContext:" + SpringContextHolder.applicationContext);
        }

        SpringContextHolder.applicationContext = applicationContext;
    }

    @Override
    public void destroy() throws Exception {
        clearHolder();
        stringValueResolver = null;
    }

    private static void assertContextInjected() {
        Validate.validState(applicationContext != null, "applicaitonContext is null, please declare SpringContextHolder bean in Spring.", new Object[0]);
    }

    public static String resolveStringPropValue(String key) {
        return resolveStringPropValue(key, (String)null);
    }

    public static String resolveStringPropValue(String key, String defaultValue) {
        if (stringValueResolver != null) {
            String keyExpression = StringUtils.isNotBlank(defaultValue) ? String.format("${%s:%s}", key, defaultValue) : String.format("${%s}", key);

            try {
                return stringValueResolver.resolveStringValue(keyExpression);
            } catch (IllegalArgumentException var4) {
                logger.debug(String.format("Cannot resolve key \"%s\" via SpringContextHolder.resolveStringPropValue(), return null", key));
                return null;
            }
        } else {
            return defaultValue;
        }
    }

    @Override
    public void setEmbeddedValueResolver(StringValueResolver resolver) {
        stringValueResolver = resolver;
    }

    @Override
    public void setEnvironment(Environment environment) {
        SpringContextHolder.environment = environment;
    }

    public static Environment getEnvironment() {
        return environment;
    }
}
