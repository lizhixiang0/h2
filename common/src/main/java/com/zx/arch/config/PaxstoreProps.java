package com.zx.arch.config;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//



import com.google.common.base.Preconditions;

/**
 * @author admin
 */
public class PaxstoreProps {
    private static final String VAS_API_PING_URL = "/v1/public/ping";
    private String authUrl;
    private String vasApiUrl;
    private boolean bypassSslCheck;
    private String authCodeProcessUrl;
    private String vasApiPingUrl;

    public PaxstoreProps() {
    }

    protected void postInit() {
        Preconditions.checkNotNull(this.authCodeProcessUrl, "authCodeProessUrl is null");
        Preconditions.checkNotNull(this.vasApiUrl, "vasApiUrl is null");
        Preconditions.checkNotNull(this.authUrl, "authUrl is null");
        this.vasApiPingUrl = this.vasApiUrl + "/v1/public/ping";
    }

    public String getAuthUrl() {
        return this.authUrl;
    }

    public String getVasApiUrl() {
        return this.vasApiUrl;
    }

    public boolean isBypassSslCheck() {
        return this.bypassSslCheck;
    }

    public String getAuthCodeProcessUrl() {
        return this.authCodeProcessUrl;
    }

    public String getVasApiPingUrl() {
        return this.vasApiPingUrl;
    }

    public void setAuthUrl(final String authUrl) {
        this.authUrl = authUrl;
    }

    public void setVasApiUrl(final String vasApiUrl) {
        this.vasApiUrl = vasApiUrl;
    }

    public void setBypassSslCheck(final boolean bypassSslCheck) {
        this.bypassSslCheck = bypassSslCheck;
    }

    public void setAuthCodeProcessUrl(final String authCodeProcessUrl) {
        this.authCodeProcessUrl = authCodeProcessUrl;
    }

    public void setVasApiPingUrl(final String vasApiPingUrl) {
        this.vasApiPingUrl = vasApiPingUrl;
    }
}
