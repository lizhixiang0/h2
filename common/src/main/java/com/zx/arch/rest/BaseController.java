package com.zx.arch.rest;

import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.context.request.WebRequest;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author lizx
 * @since 1.0.0
 * @note 抽象类的作用就是自定义一些方法，然后再抽象一些方法由子类实现
 *       抽象类由实例方法,但是无法通过new创建实例,但是其子类在创建实例对象时,会实例出抽象对象。
 **/
public abstract class BaseController {
    //springmvc并不是能对所有类型的参数进行绑定的，如果对日期Date类型参数进行绑定，就会报错IllegalStateException错误。
    //所以需要注册一些类型绑定器用于对参数进行绑定,注册有两种方式,一种是直接在Controller 里注册,另一种是在全局@ControllerAdvice里面注册

   /* @InitBinder
    public void initBinder(WebDataBinder binder, WebRequest request) {
        DateFormat dateFormat=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        binder.registerCustomEditor(Date.class, new CustomDateEditor(dateFormat, true));
    }*/
}
