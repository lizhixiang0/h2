package com.zx.arch.auth.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.zx.arch.auth.handler.ResponseHandler;
import com.zx.arch.auth.token.PaxstoreApiAuthToken;
import com.zx.arch.auth.token.TokenServiceApi;
import com.zx.arch.utils.JwtUtil;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

/**
 * @author admin
 */
public class PaxstoreApiAuthenticationFilter extends AbstractAuthFilter {
    private OrRequestMatcher requestNeedToCheckServiceEnabled = null;
    private TokenServiceApi tokenServiceApi;

    public PaxstoreApiAuthenticationFilter(String[] processingURL, ResponseHandler errorRespHandler, String[] urlNeedServiceEnabled, TokenServiceApi tokenServiceApi) {
        super(processingURL, errorRespHandler);
        this.tokenServiceApi = tokenServiceApi;
        if (ArrayUtils.isNotEmpty(urlNeedServiceEnabled)) {
            this.requestNeedToCheckServiceEnabled = new OrRequestMatcher((List)Arrays.stream(urlNeedServiceEnabled).map(AntPathRequestMatcher::new).collect(Collectors.toList()));
        }

    }

    @Override
    protected Authentication resolveAuthentication(HttpServletRequest hRequset, HttpServletResponse hRes) throws IOException {
        Authentication result = null;
        String token = hRequset.getHeader("authorization");
        String envCode = hRequset.getHeader("envCode");
        if (!StringUtils.isBlank(token) && !StringUtils.isBlank(envCode)) {
            String envCodeFromToken = JwtUtil.getClaim(token, "envCode");
            boolean checkServiceEnabled = this.requestNeedToCheckServiceEnabled != null && this.requestNeedToCheckServiceEnabled.matches(hRequset);
            if (this.tokenServiceApi.validateAccessTokenFromPaxstore(envCode, token, checkServiceEnabled) && StringUtils.equalsIgnoreCase(envCode, envCodeFromToken)) {
                result = new PaxstoreApiAuthToken(envCode);
            }
        } else {
            this.logger.info("token or envCode is blank");
        }

        return result;
    }
}
