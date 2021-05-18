package com.zx.arch.handler;

import com.zx.arch.exception.BusinessException;
import com.zx.arch.exception.ErrorCodes;
import com.zx.arch.utils.ApiUtils;
import com.zx.arch.utils.IPAddrWebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author lizx
 * @date 2020/08/06
 * @description 全局处理异常
 * @note 了解spring的异常处理机制 https://blog.csdn.net/yehongzhi1994/article/details/106797360
 *                              https://www.jianshu.com/p/f976ec4f1014
 **/
public class CustomHandlerExceptionResolver implements HandlerExceptionResolver , AccessDeniedHandler {
    private static final Logger logger = LoggerFactory.getLogger(CustomHandlerExceptionResolver.class);
    @Override
    public ModelAndView resolveException(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, Exception e) {

        //这里是一个约定,需要给用户看到的,希望给用户提示的,就用BusinessException处理,比如400
        //反之则属于未知错误,例如500这种服务器错误,不需要给用户看到
        boolean isUnknownError = false;

        //错误信息(Json字符串)
        String errorJson;
        HttpStatus status = HttpStatus.BAD_REQUEST;
        if(e instanceof BusinessException){
            BusinessException businessException = (BusinessException) e;
            errorJson = ApiUtils.getJsonMessage(status,businessException.getBusinessCode(),businessException.getMessage());
        } else{
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            errorJson = ApiUtils.getJsonMessage(status, ErrorCodes.UNKNOWN);
            isUnknownError = true;
        }
        //1、把request信息和 exception&error 打印到console,给程序员看
        logException(httpServletRequest, e, isUnknownError);

        try {
            //2、错误信息返回给前台,给用户看
            ApiUtils.writeToHttpResponse(httpServletResponse, status.value(), errorJson);
        } catch (IOException ex) {
            logException(httpServletRequest, ex, true);
        }
        return new ModelAndView();
    }

    /**
     * 将错误信息以json格式打印在console上
     * @param request
     * @param throwable 派生出exception(异常)和error(错误)。
     * @param isUnknowError
     */
    private void logException(HttpServletRequest request, Throwable throwable, boolean isUnknowError) {
        int errCode = -1;
        if (throwable instanceof BusinessException) {
            errCode = ((BusinessException) throwable).getBusinessCode();
        }
        /*
         * 在方法内使用final修饰后 因为进入一个方法是开辟一个方法栈帧 在栈帧内执行此方法，所以执行完毕后 栈帧关闭前会将final内的值清洗掉
         * 但是由于该属性已通过final修饰 并且存在于常量池内，故引用不会改变 下次获取该对象可不用重新在堆中开辟新的空间。而是直接赋值！方法执行完再清掉值
         * */
        final String errorMsg = errCode > 0 ? ApiUtils.getEnglishMessage(String.valueOf(errCode)) : throwable.getMessage();
        final String errorCode = errCode > 0 ? String.valueOf(errCode) : "UNKNOWN";
        final String msg = String.format("Received '%s', details: %s", throwable.getClass().getSimpleName(), getRequestInfo(request, errorCode, errorMsg));
        //400错误则logger.warn、500错误则logger.error
        if (isUnknowError) {
            logger.error(msg, throwable);
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

    @Override
    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        if (response.isCommitted()) {
            return;
        }
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        String errMsg = "Access denied";
        String errorJson = ApiUtils.getErrorMessage(403, errMsg);
        ApiUtils.writeToHttpResponse(response, HttpStatus.FORBIDDEN.value(), errorJson);
    }
}
