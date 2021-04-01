package com.zx.arch.resource;

import javax.annotation.Resources;

/**
 * 在 Java 的反射中，Class.forName 和 ClassLoader 的区别
 * @author lizx
 * @since 1.0.0
 * @link "https://blog.csdn.net/hupoling/article/details/90939316
 **/
public class Test01 {

    static {
        System.out.println("sss");
    }

    public static void main(String[] args) throws ClassNotFoundException {
        ClassLoader.getSystemClassLoader().loadClass("com.mybatis.lizx.TestFactory");
        Class<?> aClass = Class.forName("com.mybatis.lizx.TestFactory");
        //System.out.println(aClass);
    }
}
