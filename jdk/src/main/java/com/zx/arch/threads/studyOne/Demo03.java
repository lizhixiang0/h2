package com.zx.arch.threads.studyOne;

/**
 * @author lizx
 * @date 2020/12/06
 * @description   内置锁的可重入性
 * @note    关于子类调用父类方法,父类方法中this到底是子类对象还是父类对象的问题？
 *                  https://blog.csdn.net/kongshaohao/article/details/79654207
 *          由上面的问题引申出 为啥子类构造方法里要调用父类的构造方法？
 *                https://blog.csdn.net/weixin_42736075/article/details/106007180
 *           又由上面的问题引申出无参构造的作用是什么？
 *               https://blog.csdn.net/weixin_43758984/article/details/105538304
 *
 *
 **/
public class Demo03 {

    public static void main(String[] args) {
        B b  = new B();
        b.method1();
    }

}

class A{
    public synchronized void method1(){
        System.out.println(this);
    }
}

class B extends A{
    @Override
    public synchronized void method1(){
        System.out.println(this);
        super.method1();
    }
}
