package com.wangwenjun.concurrent.chapter10;


import org.springframework.web.servlet.tags.form.TextareaTag;

import java.sql.Driver;

/**
 * 测试类,用来测试自定义的类加载器
 *
 * java HelloWorld
 * 命令的时候，JVM会将HelloWorld.class加载到内存中，并形成一个Class的对象HelloWorld.class。
 * 其中的过程就是类加载过程：
 * 1、寻找jre目录，寻找jvm.dll，并初始化JVM；
 * 2、产生一个Bootstrap Loader（启动类加载器）；
 * 3、Bootstrap Loader自动加载Extended Loader（标准扩展类加载器），并将其父Loader设为Bootstrap Loader。
 * 4、Bootstrap Loader自动加载AppClass Loader（系统类加载器），并将其父Loader设为Extended Loader。
 * 5、最后由AppClass Loader加载HelloWorld类。
 *
 * ClassLoader 传递性
 *  程序在运行过程中，遇到了一个未知的类，它会选择哪个 ClassLoader 来加载它呢？
 *  虚拟机的策略是使用调用者 Class 对象的 ClassLoader 来加载当前未知的类。
 *  何为调用者 Class 对象？就是在遇到这个未知的类时，虚拟机肯定正在运行一个方法调用（静态方法或者实例方法），这个方法挂在哪个类上面，那这个类就是调用者 Class 对象。
 *  前面我们提到每个 Class 对象里面都有一个 classLoader 属性记录了当前的类是由谁来加载的。
 *  因为 ClassLoader 的传递性，所有延迟加载的类都会由初始调用 main 方法的这个 ClassLoader 全全负责，它就是 AppClassLoader。
 *
 * @author admin
 */
public class HelloWorld {
    static {
        String str = new String();
        System.out.println(str.getClass().getClassLoader()); // null ，根加载器是c++实现,所以是null
        Test test = new Test();
        // 由于ClassLoader的传递性,谁加载了HelloWorld，就由谁加载Test
        System.out.println(test.getClass().getClassLoader()); // My ClassLoader
    }

    public String welcome()
    {
        return "Hello World";
    }
}