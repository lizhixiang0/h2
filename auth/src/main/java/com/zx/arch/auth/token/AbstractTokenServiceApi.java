package com.zx.arch.auth.token;

import com.zx.arch.utils.JwtUtil;
import com.zx.arch.constant.VasConstants.ServiceType;
import com.zx.arch.response.PaxstoreInstanceInfo;
import org.apache.commons.lang3.StringUtils;

/**
 * @author admin
 */
public abstract class AbstractTokenServiceApi implements TokenServiceApi {
    public AbstractTokenServiceApi() {
    }

    @Override
    public String generateAccessToken(String envCode) {
        if (StringUtils.isBlank(envCode)) {
            return null;
        } else {
            String apiSecret = this.getApiSecretIssuedByPaxstore(envCode);
            return StringUtils.isBlank(apiSecret) ? null : JwtUtil.generateToken4Request2Paxstore(this.getCurrentServiceType(), apiSecret);
        }
    }

    @Override
    public boolean validateAccessTokenFromPaxstore(String token) {
        if (StringUtils.isBlank(token)) {
            return false;
        } else {
            String envCode = JwtUtil.getClaim(token, "envCode");
            return this.validateAccessTokenFromPaxstore(envCode, token, false);
        }
    }

    @Override
    public boolean validateAccessTokenFromPaxstore(String envCode, String token) {
        return this.validateAccessTokenFromPaxstore(envCode, token, false);
    }

    @Override
    public boolean validateAccessTokenFromPaxstore(String envCode, String token, boolean checkCurrentServiceEnabled) {
        if (StringUtils.isAnyBlank(new CharSequence[]{envCode, token})) {
            return false;
        } else {
            PaxstoreInstanceInfo paxstoreInstanceInfo = this.getPaxstoreInstanceInfo(envCode);
            if (checkCurrentServiceEnabled && !paxstoreInstanceInfo.isServiceEnabled(this.getCurrentServiceType())) {
                return false;
            } else {
                String secret = paxstoreInstanceInfo.getApiSecretToPaxstore();
                return StringUtils.isBlank(secret) ? false : JwtUtil.verifyTokenFromPaxstore(token, envCode, secret);
            }
        }
    }

    protected abstract PaxstoreInstanceInfo getPaxstoreInstanceInfo(String envCode);

    protected abstract ServiceType getCurrentServiceType();

    protected String getApiSecretIssuedByPaxstore(String envCode) {
        PaxstoreInstanceInfo paxstoreInstanceInfo = this.getPaxstoreInstanceInfo(envCode);
        return paxstoreInstanceInfo == null ? null : paxstoreInstanceInfo.getApiSecretFromPaxstore();
    }
}
