package com.zx.arch.utils;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.zx.arch.exception.ErrorCodes;
import com.zx.arch.response.ErrorResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * @author admin
 */
public class ApiUtils {
    private static final Logger logger = LoggerFactory.getLogger(ApiUtils.class);

    private ApiUtils() {
    }

    public static String getErrorMessage(int resultCode, String errorMessage, Object... args) {
        if (StringUtils.isBlank(errorMessage)) {
        }

        if (StringUtils.isBlank(errorMessage)) {
            errorMessage = String.valueOf(resultCode);
        }

        return errorMessage;
    }

    public static void writeToHttpResponse(HttpServletResponse response, HttpStatus httpStatus, String errorJsonBody) throws IOException {
        response.setContentType(String.valueOf(MediaType.APPLICATION_JSON));
        response.setStatus(httpStatus.value());
        if (!response.isCommitted()) {
            response.getWriter().print(errorJsonBody);
        }

    }

    public static void writeToHttpResponse(HttpServletResponse response, HttpStatus httpStatus, int errorCode) throws IOException {
        response.setContentType(String.valueOf(MediaType.APPLICATION_JSON));
        response.setStatus(httpStatus.value());
        if (!response.isCommitted()) {
            response.getWriter().print(getErrorResponseJson(errorCode));
        }

    }

    public static void writeToHttpResponse(HttpServletResponse response, HttpStatus httpStatus, int errorCode, String errorMessage) throws IOException {
        response.setContentType(String.valueOf(MediaType.APPLICATION_JSON));
        response.setStatus(httpStatus.value());
        if (!response.isCommitted()) {
            response.getWriter().print(getErrorResponseJson(errorCode, errorMessage));
        }

    }

    public static String getErrorResponseJson(int errorCode) {
        ErrorResponse response = new ErrorResponse();
        response.setErrorCode(errorCode);
        String msg = (String) ErrorCodes.CODE_MSG_MAPPING.get(errorCode);
        if (StringUtils.isBlank(msg)) {
            msg = getErrorMessage(errorCode, (String)null);
        }

        response.setMessage(msg);
        return JsonMapper.toJsonString(response);
    }

    public static String getErrorResponseJson(int errorCode, String message) {
        ErrorResponse response = new ErrorResponse(errorCode, message);
        return JsonMapper.toJsonString(response);
    }

    public static String getParameterValue(HttpServletRequest request, String key) {
        if (request != null && !StringUtils.isBlank(key) && request.getParameterMap() != null) {
            String[] parameter = (String[])request.getParameterMap().get(key);
            return parameter != null && parameter.length > 0 ? parameter[0] : null;
        } else {
            return null;
        }
    }

    public static <T> T getParameterValue(HttpServletRequest request, String key, Class<T> clazz) {
        String parameterStr = getParameterValue(request, key);
        return StringUtils.isBlank(parameterStr) ? null : JsonMapper.fromJsonString(parameterStr, clazz);
    }
    public static String getJsonMessage(HttpStatus httpStatus, int errorCode, String errorMsg) {
        return getJsonMessage(httpStatus, errorCode, errorMsg, null);
    }

    public static String getJsonMessage(HttpStatus httpStatus, int errorCode) {
        return getJsonMessage(httpStatus, errorCode, null);
    }

    /**
     * Gets error json.
     *
     * @param resultCode   the result code
     * @param errorMessage the error message
     * @param args         the message args
     * @return the error json
     */
    public static String getJsonMessage(HttpStatus httpStatus, int resultCode, String errorMessage, Object... args) {
        if(StringUtils.isBlank(errorMessage)) {
            errorMessage = getErrorMessage(resultCode, errorMessage, args);
        }
        com.zx.arch.exception.ErrorResponse errorResponse = new com.zx.arch.exception.ErrorResponse(errorMessage, resultCode, httpStatus);
        return JsonMapper.toJsonString(errorResponse);
    }

    /**
     * Gets locale message.
     *
     * @param code the code
     * @param args the args
     * @return the locale message
     */
    public static String getLocaleMessage(String code, Object... args) {
        return MessageUtils.getLocaleMessage(code, args);
    }

    /**
     * Gets english message.
     *
     * @param code the code
     * @param args the args
     * @return the english message
     */
    public static String getEnglishMessage(String code, Object... args) {
        return MessageUtils.getEnglishMessage(code, args);
    }


    /**
     * Write to http response.
     *
     * @param response      the response
     * @param status        the status
     * @param errorJsonBody the error json body
     * @throws IOException the io exception
     */
    public static void writeToHttpResponse(HttpServletResponse response, int status, String errorJsonBody) throws IOException {
        response.setContentType(String.valueOf(MediaType.APPLICATION_JSON_UTF8));
        response.setStatus(status);
        if (!response.isCommitted()) {
            response.getWriter().print(errorJsonBody);
        }
    }

    /**
     * Gets request.
     *
     * @return the request
     */
    public static HttpServletRequest getRequest() {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
    }
}
