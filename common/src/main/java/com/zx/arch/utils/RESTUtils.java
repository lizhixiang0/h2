//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.pax.support.resttemplate;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;

import com.zx.arch.exception.RestTemplateInitException;
import com.zx.arch.handler.PaxDefaultRetryHandler;
import com.zx.arch.strategy.DefaultConnKeepAliveStrategy;
import com.zx.arch.strategy.DefaultPrivateKeyStrategy;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.ResourceHttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

public class RESTUtils {
    private static final Logger logger = LoggerFactory.getLogger(RESTUtils.class);
    private static final long IDLE_TIME = 10L;
    private static final long MAX_IDLE_TIME = 10L;
    private static final String TLS_VERSION = "TLSv1.2";
    public static final String P_MSSL_KEY_STORE_PATH = "_keyStoreFilePath";
    public static final String P_MSSL_KEY_STORE_PASS = "_keyStorePass";
    public static final String P_MSSL_KEY_STORE_TYPE = "_keyStoreType";
    public static final String P_MSSL_KEY_ALIAS = "_keyAlias";
    public static final String P_MSSL_TRUST_STORE_PATH = "_trustStorePath";
    public static final String P_MSSL_TRUST_STORE_PASS = "_trustStorePath";
    public static final String P_MSSL_TRUST_STORE_TYPE = "_trustStoreType";
    private static RestTemplate nonMutualSSLRestTemplate;
    private static RestTemplate mutualSSLRestTemplate;
    private static PoolingHttpClientConnectionManager poolingHttpClientConnectionManager;

    public RESTUtils() {
    }

    private static PoolingHttpClientConnectionManager getPoolingHttpClientConnectionManager(int maxTotalConnecitons, int maxConnPerRoute) {
        Class var2 = RESTUtils.class;
        synchronized(RESTUtils.class) {
            if (poolingHttpClientConnectionManager == null) {
                poolingHttpClientConnectionManager = new PoolingHttpClientConnectionManager();
                poolingHttpClientConnectionManager.setMaxTotal(maxTotalConnecitons);
                poolingHttpClientConnectionManager.setDefaultMaxPerRoute(maxConnPerRoute);
            }
        }

        return poolingHttpClientConnectionManager;
    }

    public static RestTemplate getRestTemplate(int connectTimeout, int readTimeout, int connectionRequestTimeout, boolean mutualSSL, int retries, int maxTotalConnections, int maxConnPerRoute, boolean singleton, Map<String, String> mutualSSLParams) throws RestTemplateInitException {
        if (connectTimeout >= 0 && readTimeout >= 0 && connectionRequestTimeout >= 0 && retries >= 0 && maxTotalConnections >= 0 && maxConnPerRoute >= 0) {
            if (mutualSSL) {
                String keyStoreFilePath = ((String)mutualSSLParams.get("_keyStoreFilePath")).trim();
                String keyStorePass = ((String)mutualSSLParams.get("_keyStorePass")).trim();
                String keyStoreType = ((String)mutualSSLParams.get("_keyStoreType")).trim();
                String trustStoreFilePath = ((String)mutualSSLParams.get("_trustStorePath")).trim();
                String trustStorePass = ((String)mutualSSLParams.get("_trustStorePath")).trim();
                String trustStoreType = ((String)mutualSSLParams.get("_trustStoreType")).trim();
                if (StringUtils.isAnyBlank(new CharSequence[]{keyStoreFilePath, keyStorePass, keyStoreType, trustStoreFilePath, trustStorePass, trustStoreType})) {
                    throw new RestTemplateInitException("_keyStoreFilePath, _keyStorePass, _keyStoreType, _trustStorePath, _trustStorePath and _trustStoreType cannot be blank in construct argument 'mutualSSLParams'");
                }
            }

            return singleton ? getSingletonRestTemplate(connectTimeout, readTimeout, connectionRequestTimeout, mutualSSL, retries, maxTotalConnections, maxConnPerRoute, mutualSSLParams) : getNoneSingletonRestTemplate(connectTimeout, readTimeout, connectionRequestTimeout, mutualSSL, retries, maxTotalConnections, maxConnPerRoute, mutualSSLParams);
        } else {
            throw new RestTemplateInitException("connectTimeout, readTimeout, connectionRequestTimeout, retries, maxTotalConnections and maxConnPerRoute cannot be negative");
        }
    }

    public static RestTemplate getSingletonRestTemplate(int connectTimeout, int readTimeout, int requestTimeout, boolean mutualSSL, int retries, int maxTotalConnections, int maxConnPerRoute, Map<String, String> mutualSSLParams) throws RestTemplateInitException {
        Class var8;
        if (mutualSSL) {
            var8 = RESTUtils.class;
            synchronized(RESTUtils.class) {
                if (mutualSSLRestTemplate == null) {
                    mutualSSLRestTemplate = getNoneSingletonRestTemplate(connectTimeout, readTimeout, requestTimeout, true, retries, maxTotalConnections, maxConnPerRoute, mutualSSLParams);
                }
            }

            return mutualSSLRestTemplate;
        } else {
            var8 = RESTUtils.class;
            synchronized(RESTUtils.class) {
                if (nonMutualSSLRestTemplate == null) {
                    nonMutualSSLRestTemplate = getNoneSingletonRestTemplate(connectTimeout, readTimeout, requestTimeout, false, retries, maxTotalConnections, maxConnPerRoute, mutualSSLParams);
                }
            }

            return nonMutualSSLRestTemplate;
        }
    }

    public static RestTemplate getNoneSingletonRestTemplate(int connectTimeout, int readTimeout, int requestTimeout, boolean mutualSSL, int retries, int maxTotalConnecitons, int maxConnPerRoute, Map<String, String> mutualSSLParams) throws RestTemplateInitException {
        try {
            SSLConnectionSocketFactory sslConnectionSocketFactory = getSSLConnectionSocketFactory(mutualSSL, mutualSSLParams);
            HttpClientBuilder httpClientBuilder = HttpClients.custom().setConnectionManager(getPoolingHttpClientConnectionManager(maxTotalConnecitons, maxConnPerRoute)).setSSLSocketFactory(sslConnectionSocketFactory).setKeepAliveStrategy(getKeepAliveStrategy()).evictExpiredConnections().evictIdleConnections(10L, TimeUnit.SECONDS);
            if (retries > 0 && retries <= 5) {
                httpClientBuilder.setRetryHandler(new PaxDefaultRetryHandler(retries, true));
            }

            CloseableHttpClient httpClient = httpClientBuilder.build();
            HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
            requestFactory.setHttpClient(httpClient);
            requestFactory.setConnectTimeout(connectTimeout);
            requestFactory.setConnectionRequestTimeout(requestTimeout);
            requestFactory.setReadTimeout(readTimeout);
            RestTemplate restTemplate = new RestTemplate(requestFactory);
            List<HttpMessageConverter<?>> messageConverters = new ArrayList();
            HttpMessageConverter<Object> jackson = new MappingJackson2HttpMessageConverter();
            HttpMessageConverter<String> string = new StringHttpMessageConverter();
            HttpMessageConverter<Resource> resource = new ResourceHttpMessageConverter();
            FormHttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
            HttpMessageConverter<byte[]> ByteArrayResource = new ByteArrayHttpMessageConverter();
            messageConverters.add(formHttpMessageConverter);
            messageConverters.add(string);
            messageConverters.add(jackson);
            messageConverters.add(resource);
            messageConverters.add(ByteArrayResource);
            restTemplate.setMessageConverters(messageConverters);
            return restTemplate;
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | KeyManagementException var19) {
            logger.error("Init http client error", var19);
            throw new RestTemplateInitException(var19.getMessage(), var19);
        }
    }

    private static SSLConnectionSocketFactory getSSLConnectionSocketFactory(boolean mutualSSL, Map<String, String> parameters) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, IOException, CertificateException, UnrecoverableKeyException {
        if (mutualSSL) {
            String keyStoreFilePath = ((String)parameters.get("_keyStoreFilePath")).trim();
            String keyStorePass = ((String)parameters.get("_keyStorePass")).trim();
            String keyStoreType = ((String)parameters.get("_keyStoreType")).trim();
            String trustStoreFilePath = ((String)parameters.get("_trustStorePath")).trim();
            String trustStorePass = ((String)parameters.get("_trustStorePath")).trim();
            String trustStoreType = ((String)parameters.get("_trustStoreType")).trim();
            String keyAlias = (String)parameters.get("_keyAlias");
            KeyStore keyStore = _parseKeyStore(keyStoreFilePath, keyStorePass, keyStoreType);
            KeyStore trustStore = _parseKeyStore(trustStoreFilePath, trustStorePass, trustStoreType);
            PrivateKeyStrategy privateKeyStrategy = null;
            if (StringUtils.isNotBlank(keyAlias)) {
                privateKeyStrategy = new DefaultPrivateKeyStrategy(keyAlias.trim());
            }

            SSLContext sslcontext = SSLContexts.custom().loadKeyMaterial(keyStore, keyStorePass.toCharArray(), privateKeyStrategy).loadTrustMaterial(trustStore, new TrustSelfSignedStrategy()).build();
            return new SSLConnectionSocketFactory(sslcontext, new String[]{"TLSv1.2"}, (String[])null, NoopHostnameVerifier.INSTANCE);
        } else {
            TrustStrategy acceptingTrustStrategy = (x509Certificates, s) -> {
                return true;
            };
            SSLContext sslContext = SSLContexts.custom().loadTrustMaterial((KeyStore)null, acceptingTrustStrategy).build();
            return new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());
        }
    }

    private static KeyStore _parseKeyStore(String keystorePath, String passwd, String keyStoreType) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        Resource res = new ClassPathResource(keystorePath);
        InputStream inputStream = res.getInputStream();

        try {
            keystore.load(inputStream, passwd.toCharArray());
        } finally {
            inputStream.close();
        }

        return keystore;
    }

    private static ConnectionKeepAliveStrategy getKeepAliveStrategy() {
        return new DefaultConnKeepAliveStrategy(10L);
    }
}
