package com.zx.arch.auth.token;
/**
 * @author admin
 */
public interface TokenServiceApi {
    String generateAccessToken(String envCode) ;

    boolean validateAccessTokenFromPaxstore(String envCode, String token) ;

    boolean validateAccessTokenFromPaxstore(String envCode, String token, boolean checkCurrentServiceEnabled);

    boolean validateAccessTokenFromPaxstore(String token);
}