package com.zx.arch.auth.filter;


import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.base.Preconditions;
import com.zx.arch.auth.exception.VasAuthenticationException;

import com.zx.arch.auth.handler.ResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;


/**
 * @author admin
 * @note "https://www.freesion.com/article/7691642390/
 */
public abstract class AbstractAuthFilter extends OncePerRequestFilter {
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final OrRequestMatcher processUrlMatchers;
    private final ResponseHandler errorRespHandler;

    public AbstractAuthFilter(String[] processingURL, ResponseHandler errorRespHandler) {
        Preconditions.checkNotNull(processingURL, "Construct parameter 'processingURL' is null!");
        Preconditions.checkNotNull(errorRespHandler, "Construct parameter 'errorRespHandler' is null!");
        this.processUrlMatchers = new OrRequestMatcher((List)Arrays.stream(processingURL).map(AntPathRequestMatcher::new).collect(Collectors.toList()));
        this.errorRespHandler = errorRespHandler;
    }

    protected abstract Authentication resolveAuthentication(HttpServletRequest hReq, HttpServletResponse hRes) throws IOException;

    protected boolean requiresAuthentication(HttpServletRequest request) {
        return SecurityContextHolder.getContext().getAuthentication() == null && this.processUrlMatchers.matches(request);
    }

    protected void handleAuthFailed(Throwable ex, HttpServletRequest hreq, HttpServletResponse hres) throws IOException {
        SecurityContextHolder.clearContext();
        if (ex == null) {
            ex = new VasAuthenticationException(18);
        }

        this.errorRespHandler.handle((Throwable)ex, hreq, hres);
    }

    protected void handleAuthSuccess(Authentication auth, HttpServletRequest hreq, HttpServletResponse hres) {
        SecurityContext newContext = SecurityContextHolder.createEmptyContext();
        newContext.setAuthentication(auth);
        SecurityContextHolder.setContext(newContext);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        if (this.requiresAuthentication(httpServletRequest)) {
            Authentication auth = null;

            try {
                auth = this.resolveAuthentication(httpServletRequest, httpServletResponse);
            } catch (Exception var7) {
                this.handleAuthFailed(var7, httpServletRequest, httpServletResponse);
                return;
            }

            if (auth == null || !auth.isAuthenticated()) {
                this.handleAuthFailed((Throwable)null, httpServletRequest, httpServletResponse);
                return;
            }

            this.handleAuthSuccess(auth, httpServletRequest, httpServletResponse);
        }

        try {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        } catch (AuthenticationException var6) {
            SecurityContextHolder.clearContext();
            this.errorRespHandler.handle(var6, httpServletRequest, httpServletResponse);
        }

    }
}
