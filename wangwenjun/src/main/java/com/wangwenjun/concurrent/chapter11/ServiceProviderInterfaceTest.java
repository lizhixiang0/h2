package com.wangwenjun.concurrent.chapter11;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * @author lizx
 * @date 2021/11/30
 * @since
 * @description  SPI , 是Java提供的一套用来被第三方实现或者扩展的API，它可以用来启用框架扩展和替换组件。准确来讲就是提供这样的一个机制：为某个接口寻找服务实现的机制！
 *               JDK提供的SPI机制主要通过ServiceLoader类来实现,Dubbo也实现自己的SPI机制,Spring则是通过SpringFactoriesLoader来实现SPI机制
 *               区别：https://blog.csdn.net/yangbaggio/article/details/97617750
 *               https://blog.csdn.net/qq_35190492/article/details/108256452
 *
 * 介绍JDK的SPI机制 ：https://www.jianshu.com/p/46b42f7f593c
 *
 * 相比使用提供接口jar包，供第三方服务模块实现接口的方式，SPI的方式使得源框架，不必关心接口的实现类的路径，可以不用通过下面的方式获取接口实现类：
 * 1、代码硬编码import 导入实现类  (import就不说了)
 * 2、指定类全路径反射获取：例如在JDBC4.0之前，JDBC中获取数据库驱动类需要通过Class.forName("com.mysql.jdbc.Driver")，类似语句先动态加载数据库相关的驱动，然后再进行获取连接等的操作
 * 3、第三方服务模块把接口实现类实例注册到指定地方，源框架从该处访问实例 （spring注册bean）
 *
 * 通过SPI的方式，第三方服务模块实现接口后，在第三方的项目代码的META-INF/services目录下的配置文件指定实现类的全路径名，源码框架即可找到实现类
 *
 **/
public class ServiceProviderInterfaceTest {
    public static void main(String[] args) {
        // 点开看看ServiceLoader.load源码，可以看到
        ServiceLoader<Animal> serviceLoader = ServiceLoader.load(Animal.class);

        Iterator<Animal> iterator = serviceLoader.iterator();
        while (iterator.hasNext()){
            Animal animal = iterator.next();
            animal.eat();
        }
        // 可以看到ServiceLoader.class 是由bootstrap classLoader加载的,那么他是怎么加载那两个实现类的?
        // 可以看到ServiceLoader.load()中调用了Thread.currentThread().getContextClassLoader(),线程上下文类加载器默认就是系统类加载器! 所以答案就是它通过系统类加载器加载的
        // 这个肯定是破坏了父加载机制的（之前说过ServiceLoader.class是由bootstrap加载的，那么它加载的类也应该由bootstrap加载，但是这里不是）! 我还有一个疑问，为什么要整一个线程上下文类加载器？直接传递系统类加载器不行么?
        // 解答：主要是方便一些框架自定义类加载器！此时直接使用系统类加载器也不一定能加载到相关类。所以需要支持框架代码中 setContextClassLoader(ClassLoader custom)
        System.out.println(ServiceLoader.class.getClassLoader());
    }
}
