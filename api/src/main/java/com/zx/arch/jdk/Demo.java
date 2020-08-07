package com.zx.arch.jdk;

/**
 * @author lizx
 * @date 2020/08/04
 * @description  静态代码块、构造代码块的执行顺序
 * @result   1、静态代码块和对象没任何关系，只要class文件加载过一次，就会执行
 *          2、随着class文件加载，静态代码块和静态属性按顺序执行
 *          3、构造代码块会自动编译到构造函数里去
 **/
/*
public class Demo {
    static{
        System.out.println("静态块");
    }
    public static   Demo de2=new Demo();
    public static   Demo de3=new Demo();
    {
        System.out.println("非静态块");
    }
    public static void main(String[] args) {
        Demo de3=new Demo();
    }
}*/
/*public class Demo {
    public static  Demo de2=new Demo();
    public static  Demo de3=new Demo();
    static{
        System.out.println("静态块");
    }

    {
        System.out.println("非静态块");
    }
    public static void main(String[] args) {
        Demo de3=new Demo();
        Demo de4=new Demo();
    }
}*/
/*public class Demo {
    private Demo de1=new Demo();
    static{
        System.out.println("静态代码块");
    }
    {
        System.out.println("构造代码块");
    }
    public static void main(String[] args) {
        Demo de3=new Demo();
    }
}*/
