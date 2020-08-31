package com.zx.arch.auth.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * @author lizx
 * @date 2020/08/31
 **/
public class PaxstoreApiAuthToken extends AbstractAuthenticationToken {
    private final String envCode;

    public PaxstoreApiAuthToken(String envCode) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.envCode = envCode;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.envCode;
    }

    public String getEnvCode() {
        return this.envCode;
    }
}
