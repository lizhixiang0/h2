package com.zx.arch.jvm;

/**
 * @author lizx
 * @date 2020/08/13
 **/
public class ClassInitTest {
    private static int num = 1;
    static {
        num = 2;
        number = 20;
        System.out.println(num);
      // 报错，非法的前向引用
        //System.out.println(number);
    }

    private static int number = 10;

    public static void main(String[] args) {
        System.out.println(ClassInitTest.num);
        System.out.println(ClassInitTest.number);
    }
}
