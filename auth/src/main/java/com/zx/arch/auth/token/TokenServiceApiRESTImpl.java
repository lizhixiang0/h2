package com.zx.arch.auth.token;

import com.zx.arch.config.VasCommConfig;
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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author admin
 */
@Component
public class TokenServiceApiRESTImpl extends AbstractTokenServiceApi implements ApplicationContextAware, InitializingBean {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());
    /**
     * 本地缓存
     */
    private VasSharedInfoStorage vasSharedInfoStorage;

    protected RestTemplate restTemplate;

    protected ServiceType serviceType;

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



    @Override
    protected PaxstoreInstanceInfo getPaxstoreInstanceInfo(String envCode) {
        PaxstoreInstanceInfo paxstoreInstanceInfo = null;
        if (this.vasSharedInfoStorage != null) {
            //从本地vas缓存库中获取paxstore实例
            paxstoreInstanceInfo = (PaxstoreInstanceInfo)this.vasSharedInfoStorage.get("pax-inc-", envCode);
        }


        if(paxstoreInstanceInfo == null){
            //这个是我测试用的,自己创建了一个paxstroe实例
            paxstoreInstanceInfo = new PaxstoreInstanceInfo();
            //必须获得密钥才可以对token进行验证
            paxstoreInstanceInfo.setApiSecretFromPaxstore("ApiSecretFromPaxstore");
            paxstoreInstanceInfo.setApiSecretToPaxstore("ApiSecretToPaxstore");
            paxstoreInstanceInfo.setEnvCode(envCode);
            //调用方必须注册了本服务才认证通过
            Set<ServiceType> enabledServices = new HashSet<>();
            enabledServices.add(ServiceType.VAS_PLATFORM);
            paxstoreInstanceInfo.setEnabledServices(enabledServices);
        }
        if (paxstoreInstanceInfo == null) {
            //如果本地缓存库没有，就调用http请求到paxstore去获取，拿到后再存到本地缓存中
            paxstoreInstanceInfo = this.getPaxstoreInstanceInfoFromVas(envCode);
            if (paxstoreInstanceInfo != null && this.vasSharedInfoStorage != null) {
                this.vasSharedInfoStorage.put("pax-inc-", envCode, paxstoreInstanceInfo);
            }
        }
        return paxstoreInstanceInfo;
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

    /**
     * 从paxstore获取对应的环境实例
     * @param envCode
     * @return
     */
    private PaxstoreInstanceInfo getPaxstoreInstanceInfoFromVas(String envCode) {
        //参数
        Map<String, String> uriVariables = new HashMap(1);
        uriVariables.put("envCode", envCode);
        PaxstoreInstanceInfo paxstoreInstanceInfo = null;

        try {
            paxstoreInstanceInfo = this.exchange("/api/int/paxstore/{envCode}", HttpMethod.GET, PaxstoreInstanceInfo.class, uriVariables);
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
    public void afterPropertiesSet(){
        if (this.vasCommConfig.isCurrentServiceInSameIntranet(ServiceType.VAS_PLATFORM)) {
            this.restTemplate = this.applicationContext.getBean("loadBalancedRestTemplate", RestTemplate.class);
        } else {
            this.restTemplate = this.applicationContext.getBean("restTemplate", RestTemplate.class);
        }

    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
