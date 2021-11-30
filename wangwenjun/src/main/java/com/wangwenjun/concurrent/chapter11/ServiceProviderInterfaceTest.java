package com.wangwenjun.concurrent.chapter11;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * @author lizx
 * @date 2021/11/30
 * @since
 * @description  SPI , 是Java提供的一套用来被第三方实现或者扩展的API，它可以用来启用框架扩展和替换组件。准确来讲就是提供这样的一个机制：为某个接口寻找服务实现的机制！
 *               JDK提供的SPI机制主要通过ServiceLoader来实现,Dubbo也实现自己的SPI机制,Spring则是通过SpringFactoriesLoader来实现SPI机制
 *               区别：https://blog.csdn.net/yangbaggio/article/details/97617750
 *
 * 介绍JDK的SPI机制 ：https://www.cnblogs.com/binghe001/p/14012842.html
 **/
public class ServiceProviderInterfaceTest {
    public static void main(String[] args) {
        ServiceLoader<Animal> serviceLoader = ServiceLoader.load(Animal.class);
        Iterator<Animal> iterator = serviceLoader.iterator();
        while (iterator.hasNext()){
            Animal animal = iterator.next();
            animal.eat();
        }
    }
}
