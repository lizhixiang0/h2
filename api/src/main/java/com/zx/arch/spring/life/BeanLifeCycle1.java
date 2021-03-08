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
@blog "https://www.dazhuanlan.com/2019/12/16/5df6973d8835c/
1、通过@Component等+包扫描注册bean  (用于注册自己写的类)
2、通过@bean注解注册bean    (通常用于注册的第三方包里面的组件)
3、通过@Import注册bean
4、使用Spring提供的 FactoryBean（工厂Bean）;默认获取到的是工厂bean调用getObject创建的对象,要获取工厂Bean本身，我们需要给id前面加一个&
 */
    /*

         这里我们可以看到，如果我们需要自定义bean的初始化和对应容器销毁前后时的行为,
         有三种方式:
            1、加@PostConstruct和@PreDestroy注解
            2、实现InitializingBean和DisposableBean接口
            3、自定义init-method 和 destroyMethod 方法
          也可以同时使用这三种方式，优先级（执行顺序）按下面的来!

           1、容器刚开始bean初始化:
             Construct  实例化
             setter 填充属性

             postConstruct
            【InitializingBean接口】调用InitializingBean.afterPropertiesSet()
             init-method

        2、 容器准备进行bean的销毁:
            PreDestroy
            【DiposibleBean接口】调用DiposibleBean.destory()
            destroyMethod

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
