package com.zx.arch.jvm;

/**
 * @author lizx
 * @date 2020/08/13
 **/
public class ClassInitTest {
    private static int num = 1;

    public static void main(String[] args) {
        int num = 2;
        System.out.println(ClassInitTest.num);
    }

    public static void m(String a, String s) {
        Long e =1L;
        int num = 3;

        System.out.println(num);
    }
}
