package com.wangwenjun.concurrent.chapter10;


/**
 * 测试类,用来测试自定义的类加载器
 * @author admin
 */
public class HelloWorld
{
    static
    {
        System.out.println("Hello World Class is Initialized.");
    }

    public String welcome()
    {
        return "Hello World";
    }
}