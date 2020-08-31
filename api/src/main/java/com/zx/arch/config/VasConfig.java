package com.zx.arch.config;

import com.zx.arch.auth.token.TokenServiceApi;
import com.zx.arch.auth.token.TokenServiceApiRESTImpl;
import com.zx.arch.exception.SdkException;
import com.zx.arch.storage.VasSharedInfoStorage;
import com.zx.arch.storage.VasSharedInfoStorageLocalCache;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestTemplate;

/**
 * @author  tanjie
 * @since   1.0.0
 */
@Configuration
@Import({
        VasCommConfig.class
})
public class VasConfig {

    @Bean
    public VasSharedInfoStorage vasSharedInfoStorage() {
        return new VasSharedInfoStorageLocalCache();
    }

    @Bean
    public TokenServiceApi tokenServiceApi(VasCommConfig vasCommConfig, VasSharedInfoStorage vasSharedInfoStorage) throws
            SdkException {
        return new TokenServiceApiRESTImpl(vasCommConfig, vasSharedInfoStorage);
    }

    @Bean
    @Qualifier("restTemplate")
    public RestTemplate restTemplate(){
        return com.pax.support.resttemplate.RESTUtils.getNoneSingletonRestTemplate(5000, 5000, 5000, false, 3, 100, 20, null);
    }

    @Bean
    @Qualifier("loadBalancedRestTemplate")
    @LoadBalanced
    public RestTemplate loadBalancedRestTemplate(){
        return com.pax.support.resttemplate.RESTUtils.getNoneSingletonRestTemplate(5000, 5000, 5000, false, 3, 100, 20, null);
    }
}
