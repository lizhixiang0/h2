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
    private static int count = 1;
    public static void main(String[] args) {
        System.out.println(count);
        count++;
        main(args);
    }

    public static void m() {
        int d = 1;
        Long dd = 1L;
        long num = d+dd;

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

    public void c(){
        int i  =2;
        Integer j = 3;
        int m =i+j+1;
    }
}
