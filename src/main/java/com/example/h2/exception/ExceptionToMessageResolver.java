/*
 * *******************************************************************************
 * COPYRIGHT
 *               PAX TECHNOLOGY, Inc. PROPRIETARY INFORMATION
 *   This software is supplied under the terms of a license agreement or
 *   nondisclosure agreement with PAX  Technology, Inc. and may not be copied
 *   or disclosed except in accordance with the terms in that agreement.
 *
 *      Copyright (C) 2017 PAX Technology, Inc. All rights reserved.
 * *******************************************************************************
 */

package com.example.h2.exception;


import com.example.h2.utils.ApiUtils;
import com.example.h2.utils.IPAddrWebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * @author admin
 */
public class ExceptionToMessageResolver implements HandlerExceptionResolver{
    private static final Logger logger = LoggerFactory.getLogger(ExceptionToMessageResolver.class);

    @Override
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        logger.debug("ExceptionToMessageResolver=======================================");
        boolean isUnknowError = false;
        String errorJson;
        HttpStatus status = HttpStatus.BAD_REQUEST;
        if (ex instanceof BusinessException){
            BusinessException businessException = (BusinessException) ex;
            errorJson = ApiUtils.getJsonMessage(status,businessException.getBusinessCode(),businessException.getMessage());
        } else{
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            errorJson = ApiUtils.getJsonMessage(status, ErrorCodes.UNKNOW);
            isUnknowError = true;
        }
        logException(request, ex, isUnknowError);
        try {
            ApiUtils.writeToHttpResponse(response, status.value(), errorJson);
        } catch (IOException e1) {
            logException(request, e1, true);
        }
        return new ModelAndView();
    }


    private void logException(HttpServletRequest request, Throwable t, boolean isUnknowError) {
        int errCode = -1;
        if (t instanceof BusinessException) {
            errCode = ((BusinessException) t).getBusinessCode();
        }
        final String errorMsg = errCode > 0 ? ApiUtils.getEnglishMessage(String.valueOf(errCode)) : t.getMessage();
        final String errorCode = errCode > 0 ? String.valueOf(errCode) : "UNKNOWN";
        final String msg = String.format("Received '%s', details: %s", t.getClass().getSimpleName(), getRequestInfo(request, errorCode, errorMsg));
        if (isUnknowError) {
            logger.error(msg, t);
        } else {
            logger.warn(msg);
        }
    }

    private String getRequestInfo(HttpServletRequest request, String errorCode, String msg) {
        return (new StringBuilder("\n--------------------"))
                .append("\n req ip: ").append(IPAddrWebUtils.getRealIP(request))
                .append("\n req url: ").append(request.getRequestURL())
                .append("\n req method: ").append(request.getMethod())
                .append("\n biz code: ").append(errorCode)
                .append("\n message: ").append(msg)
                .append("\n--------------------")
                .toString();
    }
}
