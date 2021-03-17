package com.zx.arch.jvm;

/**
 * 光标必须位于类体内，View-Show ByteCode
 * @author lizx
 * @date 2020/08/13
 **/
public class ClassInitTest {
    private static int num = 1;


    static {
        String a ="d";
    }
    private static int count = 1;
    public void main(String[] args) {
        System.out.println(count);
        count++;
        main(args);
    }

    public  void m() {
        int d = 1;
        //对象类型的局部变量只占据一个槽
        Long dd = 1L;
        //long类型占据两个槽位，并且在操作栈中也占两个位
        Long num = d+dd;

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
