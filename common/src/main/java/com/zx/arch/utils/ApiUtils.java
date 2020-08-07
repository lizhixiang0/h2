package com.zx.arch.utils;

import com.zx.arch.exception.ErrorResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * API Json Utils
 *
 * @author zhihao
 */
public class ApiUtils {

    protected static Logger logger = LoggerFactory.getLogger(ApiUtils.class);

    private ApiUtils() {
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
        ErrorResponse errorResponse = new ErrorResponse(errorMessage, resultCode, httpStatus);
        return JsonMapper.toJsonString(errorResponse);
    }


    /**
     * Gets error message.
     *
     * @param resultCode the result code
     * @return the error message
     */
    public static String getErrorMessage(int resultCode) {
        return getErrorMessage(resultCode, null);
    }

    /**
     * Gets error message.
     *
     * @param resultCode   the result code
     * @param errorMessage the error message
     * @param args         the message args
     * @return the error message
     */
    public static String getErrorMessage(int resultCode, String errorMessage, Object... args) {
        if (StringUtils.isBlank(errorMessage)) {
            errorMessage = getLocaleMessage(String.valueOf(resultCode), args);
        }

        if (StringUtils.isBlank(errorMessage)) {
            errorMessage = String.valueOf(resultCode);
        }

        return errorMessage;
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
