package com.zx.arch.auth.token;

import com.zx.arch.config.VasCommConfig;
import com.zx.arch.constant.VasConstants;
import com.zx.arch.constant.VasConstants.ServiceType;
import com.zx.arch.exception.SdkException;
import com.zx.arch.response.PaxstoreInstanceInfo;
import com.zx.arch.utils.RestSdkUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.NestedRuntimeException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import com.zx.arch.storage.VasSharedInfoStorage;

import java.util.HashMap;
import java.util.Map;
/**
 * @author admin
 */
@Component
public class TokenServiceApiRESTImpl extends AbstractTokenServiceApi implements ApplicationContextAware, InitializingBean {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());
    private VasSharedInfoStorage vasSharedInfoStorage;
    protected RestTemplate restTemplate;
    protected VasConstants.ServiceType serviceType;
    final String vasPlatformApiBaseUrl;
    protected String tokenSignKey;
    private VasCommConfig vasCommConfig;
    private ApplicationContext applicationContext;

    public TokenServiceApiRESTImpl(VasCommConfig vasCommConfig, VasSharedInfoStorage vasSharedInfoStorage) throws SdkException {
        if (vasCommConfig == null) {
            throw new SdkException(200000);
        } else {
            this.serviceType = vasCommConfig.getCurrentServiceType();
            this.vasPlatformApiBaseUrl = vasCommConfig.getServiceApiBaseUrl(ServiceType.VAS_PLATFORM);
            this.tokenSignKey = vasCommConfig.getCurrentServiceSecurityKey();
            this.vasSharedInfoStorage = vasSharedInfoStorage;
            this.vasCommConfig = vasCommConfig;
        }
    }

    protected <T> T exchange(String url, HttpMethod method, Class<T> responseType, Map<String, ?> uriVariables) throws SdkException {
        try {
            HttpHeaders requestHeaders = RestSdkUtils.prepareRequestHeader(this.tokenSignKey, this.getCurrentServiceType());
            HttpEntity requestEntity = new HttpEntity((Object)null, requestHeaders);
            return this.restTemplate.exchange(RestSdkUtils.concatUrl(this.vasPlatformApiBaseUrl, url), method, requestEntity, responseType, uriVariables).getBody();
        } catch (NestedRuntimeException var7) {
            throw RestSdkUtils.convertException(var7);
        }
    }

    @Override
    protected PaxstoreInstanceInfo getPaxstoreInstanceInfo(String envCode) {
        PaxstoreInstanceInfo paxstoreInstanceInfo = null;
        if (this.vasSharedInfoStorage != null) {
            paxstoreInstanceInfo = (PaxstoreInstanceInfo)this.vasSharedInfoStorage.get("pax-inc-", envCode);
        }

        if (paxstoreInstanceInfo == null) {
            paxstoreInstanceInfo = this.getPaxstoreInstanceInfoFromVas(envCode);
            if (paxstoreInstanceInfo != null && this.vasSharedInfoStorage != null) {
                this.vasSharedInfoStorage.put("pax-inc-", envCode, paxstoreInstanceInfo);
            }
        }

        return paxstoreInstanceInfo;
    }

    private PaxstoreInstanceInfo getPaxstoreInstanceInfoFromVas(String envCode) {
        Map<String, String> uriVariables = new HashMap(1);
        uriVariables.put("envCode", envCode);
        PaxstoreInstanceInfo paxstoreInstanceInfo = null;

        try {
            paxstoreInstanceInfo = (PaxstoreInstanceInfo)this.exchange("/api/int/paxstore/{envCode}", HttpMethod.GET, PaxstoreInstanceInfo.class, uriVariables);
        } catch (SdkException var5) {
            this.logger.error("Encounter error when get paxstore instance info from vas", var5);
        }

        return paxstoreInstanceInfo;
    }

    @Override
    protected ServiceType getCurrentServiceType() {
        return this.vasCommConfig.getCurrentServiceType();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (this.vasCommConfig.isCurrentServiceInSameIntranet(ServiceType.VAS_PLATFORM)) {
            this.restTemplate = (RestTemplate)this.applicationContext.getBean("loadBalancedRestTemplate", RestTemplate.class);
        } else {
            this.restTemplate = (RestTemplate)this.applicationContext.getBean("restTemplate", RestTemplate.class);
        }

    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {

    }
}
