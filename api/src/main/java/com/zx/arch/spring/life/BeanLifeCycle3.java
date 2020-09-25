package com.zx.arch.spring.life;

import org.springframework.beans.BeansException;
import org.springframework.beans.PropertyValues;
import org.springframework.beans.factory.config.InstantiationAwareBeanPostProcessor;

/**
 * @author lizx
 * @since 1.0.0
 * @description InstantiationAwareBeanPostProcessor是BeanPostProcessor的子接口，扩展了三个方法
 *
 *              可以在每个Bean生命周期的实例化前后做手脚
 *              即Construct实例化Bean之前（调用postProcessBeforeInstantiation方法）
 *              和Construct实例化Bean之后（调用postProcessAfterInstantiation方法）
 *
 *              另外补充的postProcessProperties()方法,可以在每个Bean注入属性之后 ,对其属性动手脚！
 *
 *
 *              这也是一个全局地图炮！共荣处理器！
 *
 *
 **/
//@Component
public class BeanLifeCycle3 implements InstantiationAwareBeanPostProcessor {

    @Override
    public Object postProcessBeforeInstantiation(Class<?> beanClass, String beanName) throws BeansException {
        System.out.println("InstantiationAwareBeanPostProcessor接口方法postProcessBeforeInstantiation对属性进行更改！");
        return null;
    }

    @Override
    public PropertyValues postProcessProperties(PropertyValues pvs, Object bean, String beanName)
            throws BeansException {
        //null，相当于什么都没做
        //返回不是null，相当于将返回的变量值替换原来的变量赋值
        System.out.println("sss");
        return null;
    }
}
