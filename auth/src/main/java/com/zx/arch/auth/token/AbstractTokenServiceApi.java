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
        //验证两个参数非空非null
        //String继承了CharSequence，但CharSequence的值是可读可写序列，而String的值是只读序列
        if (StringUtils.isAnyBlank(new CharSequence[]{envCode, token})) {
            return false;
        } else {
            //根据env获取对应的paxstore实例
            PaxstoreInstanceInfo paxstoreInstanceInfo = this.getPaxstoreInstanceInfo(envCode);
            //判断实例是否订阅此服务
            if (checkCurrentServiceEnabled && !paxstoreInstanceInfo.isServiceEnabled(this.getCurrentServiceType())) {
                return false;
            } else {
                //获取实例密钥
                String secret = paxstoreInstanceInfo.getApiSecretToPaxstore();
                //根据实例密钥，token、envcode判断token是否为paxstore发出
                return StringUtils.isBlank(secret) ? false : JwtUtil.verifyTokenFromPaxstore(token, envCode, secret);
            }
        }
    }

    protected abstract PaxstoreInstanceInfo getPaxstoreInstanceInfo(String envCode);

    /**
     * 获取当前服务类型，这个配置在application中，通过Configuration赋值
     * @return
     */
    protected abstract ServiceType getCurrentServiceType();

    protected String getApiSecretIssuedByPaxstore(String envCode) {
        PaxstoreInstanceInfo paxstoreInstanceInfo = this.getPaxstoreInstanceInfo(envCode);
        return paxstoreInstanceInfo == null ? null : paxstoreInstanceInfo.getApiSecretFromPaxstore();
    }
}
