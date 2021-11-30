package com.wangwenjun.concurrent.chapter10;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static java.lang.ClassLoader.getSystemClassLoader;
import static java.lang.Thread.currentThread;

/***************************************
 * @author:Alex Wang
 * @Date:2017/11/20
 * QQ: 532500648
 * QQ群:463962286
 ***************************************/
public class MyClassLoaderTest {

    public final static String MY_CLASS_LOADER_PATH = "D:\\JetBrains\\workspace\\h2\\wangwenjun\\target\\classes\\";
    /**
     * 测试自己的类加载器,注意绕过系统类加载器
     * @throws ClassNotFoundException
     * @throws NoSuchMethodException
     * @throws IllegalAccessException
     * @throws InstantiationException
     * @throws InvocationTargetException
     */
    public static void test_my_classLoader() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException {
        // 需要设置父类加载器为null,不然这个类会被系统类加载器加载到(系统类加载器的加载路径包括MY_CLASS_LOADER_PATH) ，也可以将扩展类加载器设置成MyClassLoader的父加载器
        MyClassLoader classLoader = new MyClassLoader(MY_CLASS_LOADER_PATH,null);
        // loadClass属于类加载整个生命周期的加载阶段,不会触发类的初试化，换句话说加载类不会执行静态代码块中的方法
        Class<?> bClass = classLoader.loadClass("com.wangwenjun.concurrent.chapter10.HelloWorld");
        System.out.println(bClass.getClassLoader() == classLoader); // true
        bClass.newInstance();
    }

    /**
     * Java 虚拟机不仅要看类的全名是否相同，还要看加载此类的类加载器是否一样。只有两者都相同的情况，才认为两个类是相同的
     * 每个类加载器都有自己的命名空间！命名空间由该加载器以及所有父加载器构成
     * 我们通常说每个class实例在JVM中只有一份是不严谨的，准确来讲，应该是同一个class实例在同一个类加载器命名空间下是唯一的!
     *
     * @throws ClassNotFoundException
     */
    public static void test_two_my_classLoader() throws ClassNotFoundException {
        // 创建一个类加载器实例
        MyClassLoader classLoader = new MyClassLoader(MY_CLASS_LOADER_PATH, null);
        Class<?> aClass = classLoader.loadClass("com.wangwenjun.concurrent.chapter10.HelloWorld");

        // 创建一个类加载器实例
        MyClassLoader classLoader2 = new MyClassLoader(MY_CLASS_LOADER_PATH, null);
        Class<?> bClass = classLoader2.loadClass("com.wangwenjun.concurrent.chapter10.HelloWorld");

        // 可以看到两个class实例是不一样的
        System.out.println(aClass == bClass); // false
    }

    /**
     * 了解什么是运行时包
     * 由同一类装载器装载的属于相同包的类组成了运行时包，只有属于同一运行时包的类才能互相访问包可见的类和成员！
     * 决定两个类是不是属于同一个运行时包，不仅要看它们的包名是否相同，还要看类装载器是否相同
     *
     * 那么，为什么我们自己在自己定义的包下可以访问java.lang包里面的类或者方法？比如String ？？
     * 因为在类的加载过程中,所有参与过的类加载器，即使没有亲自加载过该类，也都会标识为该类的初试类加载器 ！
     * 也就是说，String的确不是系统类加载器加载的，但是她是经过系统类加载器向上通过根加载器加载的！系统类加载器维护的class列表中也会有一份String ！
     *
     * 比如 Driver接口是bootstrap加载的,它的实现类是ContextClassLoader加载的，那为啥他俩可以无缝衔接？
     * 其实也可以解释,实现类是经过bootstrap向下通过ContextClassLoader加载的,所以bootstrap classLoader的class列表也维护了一份driver实现类
     * 只不过这里使用ContextClassLoader破坏了父加载机制，但是运行时包依旧遵守。
     *
     */
    public static void test_runtime_package(){
        // 如何打印类的运行时包？
    }


    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InstantiationException, NoSuchMethodException, InvocationTargetException, InterruptedException {
        test_my_classLoader();
    }
}