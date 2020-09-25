package com.zx.arch.spring.life;

import org.springframework.beans.factory.*;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

/**
 * @author lizx
 * @since 1.0.0
 * @description 自定义bean的行为  系列一
 * @note   "https://www.cnblogs.com/zrtqsk/p/3735273.html
 * @result
 *
/*
"https://www.dazhuanlan.com/2019/12/16/5df6973d8835c/?__cf_chl_jschl_tk__=2deb28a6c27b218a8b3478107134f06cf74abc38-1601045684-0-AaR-eYjPXmniFqPEnIju1QuBU1xW2GFWe53bA8cwNllVx5aqH8dS33KpR4WGwhUYSEZqqMaztO0bCR1B3MYiR-U2FcyIT7G01oXytwDmDYlNmlUjZzxbw6Zy2urMNeZIupMcA6dyiuyf8mdPQHtG2FQCoRplF79sFC7JbTwCWRRmz1P3X1f9P2_bjGDylyW2ReSDO2sA8qAvZpCna-8k2Z88WstRGINv17pAmidWLgUe48pzDzJEevFSBBhUcf4SA_1Wtc4EWJVapy7RylGe36Km0Y8_9_Z0eMtJ5zKumMv7CWpcO6Z6f978WRfjcCGAQQ
1、通过@Component等+包扫描注册bean  (用于注册自己写的类)
2、通过@bean注解注册bean    (通常用于注册的第三方包里面的组件)
3、通过@Import注册bean
4、使用Spring提供的 FactoryBean（工厂Bean）;默认获取到的是工厂bean调用getObject创建的对象,要获取工厂Bean本身，我们需要给id前面加一个&
 */
    /*
         1、容器初始化:
             Construct
             setter

             postConstruct
            【InitializingBean接口】调用InitializingBean.afterPropertiesSet()
             init-method

        2、 容器销毁:
            PreDestroy
            【DiposibleBean接口】调用DiposibleBean.destory()
            destroyMethod


         这里我们可以看到，如果我们需要自定义bean的初始化和对应容器销毁时的行为,有三种方式:
            1、加@PostConstruct和@PreDestroy注解
            2、实现InitializingBean和DisposableBean接口
            3、自定义init-method 和 destroyMethod 方法
          也可以同时使用这三种方式，优先级按上面的来!
    * */
//@Component
public class BeanLifeCycle1 implements InitializingBean, DisposableBean{

    private int age;

    public BeanLifeCycle1(){
        System.out.println("Construct");
    }

    public void setAge(int age) {
        System.out.println("setter");
        this.age = age;
    }

    @PostConstruct
    public void postConstruct() {

        System.out.println("postConstruct");
    }

    public void myInitMethod() {
        System.out.println("init-method");
    }

    @Override
    public void afterPropertiesSet()  {
        System.out.println("【InitializingBean接口】调用InitializingBean.afterPropertiesSet()");
    }

    @PreDestroy
    public void PreDestroy() {
        System.out.println("PreDestroy");
    }

    public void myDestroyMethod() {
        System.out.println("destroyMethod");
    }

    @Override
    public void destroy() {
        System.out.println("【DiposibleBean接口】调用DiposibleBean.destory()");
    }
}
