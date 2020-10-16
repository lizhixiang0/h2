package com.zx.arch.spring.life;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;

/**
 * @author lizx
 * @since 1.0.0
 * @description 对BeanFactory进行操作的处理器！！
 *              允许我们在所有的bean被加载进容器进来后但是还没初始化前，对任意bean的属性进行修改或add属性值。
 *              注意,可以配置多个BeanFactoryPostProcessor的实现类，通过”order”控制执行次序
 *
 *              这不是地图炮。只在所有bean被注册到容器之后，初始化之前执行一次。
 *
 * @note 不支持@bean注册的bean.
 **/
@Component
public class BeanLifeCycle4 implements BeanFactoryPostProcessor {

    public BeanLifeCycle4(){
        System.out.println("看看是实例化之前还是实例化之后");
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        String[] strings =  beanFactory.getBeanDefinitionNames();
        //Arrays.stream(strings).forEach(i-> System.out.println(i));
        BeanDefinition beanDefinition = beanFactory.getBeanDefinition("beanLifeCycle4");
        beanDefinition.getPropertyValues().add("name", "大宝");
    }
}
