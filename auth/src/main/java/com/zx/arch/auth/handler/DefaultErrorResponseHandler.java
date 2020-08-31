package com.zx.arch.auth.handler;


import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.zx.arch.exception.GenericVasException;
import com.zx.arch.auth.exception.ThirdpartyAuthenticationException;
import com.zx.arch.auth.exception.VasAuthenticationException;

import com.zx.arch.utils.ApiUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

/**
 * @author admin
 */
public class DefaultErrorResponseHandler implements ResponseHandler {
    private static final Logger logger = LoggerFactory.getLogger(DefaultErrorResponseHandler.class);

    public DefaultErrorResponseHandler() {
    }

    @Override
    public void handle(Throwable exception, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!(exception instanceof ThirdpartyAuthenticationException) && !(exception instanceof VasAuthenticationException)) {
            if (exception instanceof GenericVasException) {
                ApiUtils.writeToHttpResponse(response, HttpStatus.BAD_REQUEST.value(), ((GenericVasException)exception).getMessage());
            } else {
                logger.error("Encounter unknow exception", exception);
                ApiUtils.writeToHttpResponse(response, HttpStatus.BAD_REQUEST.value(),"");
            }
        } else {
            ApiUtils.writeToHttpResponse(response, HttpStatus.UNAUTHORIZED.value(), ((VasAuthenticationException)exception).getMessage());
        }
    }
}

