package com.zx.arch.spring.life;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.*;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

/**
 * @author lizx
 * @since 1.0.0
 * @description 自定义bean的行为
 * @note   "https://www.cnblogs.com/zrtqsk/p/3735273.html
 **/
//@Component
public class BeanLifeCycle implements InitializingBean, DisposableBean{
    private int age;

    private BeanFactory beanFactory;

    private String beanName;

    public BeanLifeCycle(){
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

    /*
      1、通过@Component方式注册bean
      2、通过@bean注解注册bean
      3、通过@Import注册bean
     */

    /*
         1、容器创建:
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
}
