package com.zx.arch.spring.life;


import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * @author lizx
 * @since 1.0.0
 * @description 介绍bean的后置处理器
 * @note     简单理解:
 *               spring会自动从它的所有的bean定义中检测所有实现了BeanPostProcessor的bean,然后实例化这些bean
 *               ，然后在执行这些bean的初始化前后,都会
 *               在bean的init初始化方法回调之前调用BeanPostProcessor的postProcessBeforeInitialization的方法！
 *               在bean实例的init初始化方法回调之后调用BeanPostProcessor的postProcessAfterInitialization的方法！
 *                 （类似bean的代理，应用BeanPostProcessor于随后创建的每一个bean实例）
 *
 *           通俗来讲就是,一处点火，处处开花。
 *           所以通常我们不会用一个pojo  bean去实例化这个接口,而是专门定义一个处理器Processor !我叫他共荣处理器！
 *
 *           网上讲到的一些应用,其中一个是通过后置处理器来处理同一个接口有多个实现类的bean注入问题（处理器处理的是变量！）
 * @note "https://blog.csdn.net/geekjoker/article/details/79868945?utm_medium=distribute.pc_relevant.none-task-blog-title-1&spm=1001.2101.3001.4242
 **/
//@Component
public class BeanLifeCycle2 implements BeanPostProcessor {

    @Override
    public  Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("BeanPostProcessor接口方法postProcessBeforeInitialization对属性进行更改！");
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("BeanPostProcessor接口方法postProcessAfterInitialization对属性进行更改！");
        return bean;
    }
}
