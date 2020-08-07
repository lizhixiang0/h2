package com.zx.arch.jdk;

/**
 * @author lizx
 * @date 2020/08/04
 * @Description 测试工具类中静态代码块执行
 *
 * @result   只要调用了工具类，静态代码块即执行
 **/
public class Demo2 {
    static{
        System.out.println("我是大哥大");
    }
    private Demo2(){}

    public static void test(){
        System.out.println("??");
    }

    public static void main(String[] args) {
        Demo2.test();
    }
}


