package com.zx.arch.review;

/**
 * @author lizx
 * @date 2020/07/26
 * @Desscrption 测试接口
 **/
public interface InterfaceTest {
    /**
     * 修饰符必须是default
     */
    default  void test(){
        System.out.println("jdk1.8之后，接口允许有默认方法,但是这个默认方法必须是对所有实现类都有价值");
    };

    class Test01 implements  InterfaceTest{
        public static void main(String[] args) {
            InterfaceTest demoTest01 = new Test01();
            demoTest01.test();
        }
    }
}


