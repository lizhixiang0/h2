package com.zx.arch.utils;

import com.zx.arch.constant.VasConstants;
import com.zx.arch.exception.SdkException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;

/**
 * @author admin
 */
public class RestSdkUtils {
    private static final Logger logger = LoggerFactory.getLogger(RestSdkUtils.class);
    private static final String URL_SPLIT = "/";

    private RestSdkUtils() {
    }

    public static SdkException convertException(Exception e) {
        logger.warn(e.getMessage(), e);
        if (e instanceof HttpClientErrorException) {
            logger.warn(((HttpClientErrorException)e).getResponseBodyAsString(), e);
            return new SdkException(1, ((HttpClientErrorException)e).getResponseBodyAsString());
        } else if (e instanceof HttpServerErrorException) {
            logger.warn(((HttpServerErrorException)e).getResponseBodyAsString(), e);
            return new SdkException(2);
        } else if (e instanceof RestClientException) {
            logger.warn(e.getMessage(), e);
            return new SdkException(3, e.getMessage());
        } else {
            return new SdkException(e);
        }
    }

    public static String concatUrl(String baseUrl, String url) {
        if (StringUtils.isBlank(url)) {
            return baseUrl;
        } else if (StringUtils.endsWith(baseUrl, "/")) {
            return StringUtils.startsWith(url, "/") ? baseUrl + url.replaceFirst("/", "") : baseUrl + url;
        } else {
            return StringUtils.startsWith(url, "/") ? baseUrl + url : baseUrl + "/" + url;
        }
    }

    public static HttpHeaders prepareRequestHeader(String tokenSignKey, VasConstants.ServiceType serviceType) {
        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.setContentType(MediaType.APPLICATION_JSON);
        if (StringUtils.isNotEmpty(tokenSignKey)) {
            String token = JwtUtil.generateVasInternalToken(serviceType, tokenSignKey);
            requestHeaders.add("accessToken", token);
            requestHeaders.add("serviceType", serviceType.getValue());
        }

        return requestHeaders;
    }
}
