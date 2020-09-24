package com.zx.arch.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.zx.arch.constant.VasConstants.ServiceType;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
    /**
     * 默认token过期时间一个小时
     */
    private static final long DEFAULT_TOKEN_EXPIRE_TIME = 3600000L;

    private JwtUtil() {
    }

    /**
     * 根据服务类型和密钥生成 访问paxstore的token
     * @param serviceType
     * @param secret
     * @param expireInMillis
     * @return
     */
    public static String generateToken4Request2Paxstore(ServiceType serviceType, String secret, long expireInMillis) {
        try {
            Date date = new Date(System.currentTimeMillis() + expireInMillis);
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create().withClaim("serviceType", serviceType.getValue()).withExpiresAt(date).sign(algorithm);
        } catch (UnsupportedEncodingException var6) {
            logger.info("Encounter error when create token", var6);
            return null;
        }
    }

    public static String generateToken4Request2Paxstore(ServiceType serviceType, String secret) {
        return generateToken4Request2Paxstore(serviceType, secret, DEFAULT_TOKEN_EXPIRE_TIME);
    }

    /**
     * 根据服务类型和密钥以及当前user生成 访问paxstore的token
     * @param serviceType
     * @param currentUser
     * @param secret
     * @param expireInMillis
     * @return
     */
    public static String generateToken4Request2Paxstore(ServiceType serviceType, String currentUser, String secret, long expireInMillis) {
        try {
            Date date = new Date(System.currentTimeMillis() + expireInMillis);
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create().withClaim("serviceType", serviceType.getValue()).withClaim("current-user", currentUser).withExpiresAt(date).sign(algorithm);
        } catch (UnsupportedEncodingException var7) {
            logger.info("Encounter error when create token", var7);
            return null;
        }
    }

    public static String generateToken4Request2Paxstore(ServiceType serviceType, String currentUser, String secret) {
        return generateToken4Request2Paxstore(serviceType, currentUser, secret, DEFAULT_TOKEN_EXPIRE_TIME);
    }

    public static boolean verifyTokenFromPaxstore(String token, String envCode, String secret) {
        try {
            //构建密钥信息
            Algorithm algorithm = Algorithm.HMAC256(secret);
            //通过密钥信息和签名的发布者的信息生成验证类
            JWTVerifier verifier = JWT.require(algorithm).withClaim("serviceType", envCode).build();
            verifier.verify(token);
            return true;
        } catch (Exception var5) {
            logger.info("verify token fail", var5);
            return false;
        }
    }

    public static boolean verifyTokenFromVas(String token, String secret) {
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret)).build();
            verifier.verify(token);
            return true;
        } catch (Exception var3) {
            logger.info("verify token fail", var3);
            return false;
        }
    }

    public static String getClaim(String token, String claimName) {
        Optional<DecodedJWT> decodedJWT = Optional.ofNullable(JWT.decode(token));
        if (decodedJWT.isPresent() && StringUtils.isNotBlank(claimName)) {
            Optional<Claim> claim = Optional.ofNullable(((DecodedJWT)decodedJWT.get()).getClaim(claimName));
            return claim.isPresent() ? ((Claim)claim.get()).asString() : null;
        } else {
            return null;
        }
    }

    /**
     * 生成vas内联令牌
     * @param serviceType
     * @param secret
     * @param expireInMillis
     * @return
     */
    public static String generateVasInternalToken(ServiceType serviceType, String secret, long expireInMillis) {
        Map<String, String> claims = new HashMap(1);
        claims.put("serviceType", serviceType.getValue());
        return generateToken(claims, secret, expireInMillis);
    }


    public static String generateVasInternalToken(ServiceType serviceType, String secret) {
        return generateVasInternalToken(serviceType, secret, 3600000L);
    }

    /**
     * 生成秘钥！！！这个secret是双方约定好的！
     * header 头里需要带(格式一定要对！！)
     * {
     * Authorization:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzZXJ2aWNlVHlwZSI6ImFwcF9zY2FuIiwiZXhwIjoxNjAwOTUwOTgwfQ.aOeTDp4e-o4DX0PHaQ3pr9dTpI7nl0_yW-7jtsZDvqo
     * envCode:app_scan
     * }
     * 另外注意,RestServices这个IDEA插件不需要加双引号和逗号，我因为这个浪费很多时间,麻痹的。
     *
     * @param args
     */
    public static void main(String[] args) {
        System.out.println(
                String.format("{\r\nAuthorization:%s\r\nenvCode:app_scan\r\n}",generateVasInternalToken(ServiceType.APP_SCAN,"ApiSecretToPaxstore"))

                );
    }

    public static String generateToken(Map<String, String> claims, String secret, long expireInMillis) {
        try {
            Date date = new Date(System.currentTimeMillis() + expireInMillis);
            Algorithm algorithm = Algorithm.HMAC256(secret);
            Builder builder = JWT.create().withExpiresAt(date);
            claims.forEach(builder::withClaim);
            return builder.sign(algorithm);
        } catch (IllegalArgumentException | UnsupportedEncodingException var7) {
            logger.error("Generate token failed", var7);
            return null;
        }
    }

    public static String generateToken(Map<String, String> claims, String secret) {
        return generateToken(claims, secret, 3600000L);
    }
}
