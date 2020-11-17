package com.zx.arch.jdk;

/**
 * @author lizx
 * @since 1.0.0
 * @description 测试 instance of
 * @note 谨慎使用lombok的@Date ,因为一些扫描报告会扫出这里面的equals()有问题，因为里面的改写的equals方法调用了instanceof函数
 *       换句话说,lombok判断两个类是否equals,是根据instanceof函数来的,那么这样靠谱吗？
 *       不靠谱！！！因为在某些情况下不满足对称性！
 **/
public class EqualsTest {

    static  class A {
        @Override
        public boolean equals(Object obj) {
            return obj instanceof A;
        }
    }

    static class B extends A{
        @Override
        public boolean equals(Object obj) {
            return obj instanceof B;
        }
    }

    public static void main(String[] args) {
        A a = new A();
        B b = new B();
        System.out.println(a.equals(b));
        System.out.println(b.equals(a));
    }
}
