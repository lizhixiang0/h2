package com.zx.arch.config;

import com.google.common.base.Preconditions;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author admin
 */
@Data
@NoArgsConstructor
public class PaxstoreProps {
    private static final String VAS_API_PING_URL = "/v1/public/ping";
    private String authUrl;
    private String vasApiUrl;
    private boolean bypassSslCheck;
    private String authCodeProcessUrl;
    private String vasApiPingUrl;

    protected void postInit() {
        Preconditions.checkNotNull(this.authCodeProcessUrl, "authCodeProessUrl is null");
        Preconditions.checkNotNull(this.vasApiUrl, "vasApiUrl is null");
        Preconditions.checkNotNull(this.authUrl, "authUrl is null");
        this.vasApiPingUrl = this.vasApiUrl + "/v1/public/ping";
    }
}
