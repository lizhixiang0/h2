package com.zx.arch.jvm;

/**
 * @author lizx
 * @date 2020/08/13
 **/
public class ClassInitTest {
    private static int num = 1;


    static {
        String a ="d";
    }
    public static void main(String[] args) {
        int num = 2;
        System.out.println(ClassInitTest.num);
    }

    public static void m(String a, String s) {
        double e = 1.00;
        long d = 1L;
        int num = 3;

        System.out.println(num);
    }
    public void test(){
        int w = 1;
        // 验证slot 的重复利用问题 ,变量a在方法内部销毁了,所以他在局部变量表的位置空出来了,然后给了c
        {
            int a = 0;
            a = w+1;
        }
        int c = 3;
    }
    private ClassInitTest(){}
}
