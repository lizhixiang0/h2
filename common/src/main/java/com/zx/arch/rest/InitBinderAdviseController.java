package com.zx.arch.rest;

import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.context.request.WebRequest;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author lizx
 * @since 1.0.0
 * @description   这是SpringMVC中的一个增强的 Controller
 *                     1、全局异常处理
 *                     2、全局数据绑定
 *                     3、全局数据预处理
 * @blog  "https://www.cnblogs.com/lenve/p/10748453.html
 **/
@ControllerAdvice
public class InitBinderAdviseController {
    /*@InitBinder
    public void initBinder(WebDataBinder binder, WebRequest request) {
        DateFormat dateFormat=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        binder.registerCustomEditor(Date.class, new CustomDateEditor(dateFormat, true));
    }*/
}
