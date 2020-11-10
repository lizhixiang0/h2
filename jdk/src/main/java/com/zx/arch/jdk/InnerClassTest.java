package com.zx.arch.jdk;

import lombok.SneakyThrows;

/**
 * @author lizx
 * @since 1.0.0
 * @description 测试内部类的作用
 * @blog "https://www.zhihu.com/question/26954130
 **/
public class InnerClassTest {

    private String a = "aa";


    /**
     * NO.1 如果只是想用某个类中的方法,比如 Thread 中的run() ,使用内部类可以少写一个类
     */
    public void useThreadRunMethod1(){
        String b = "bb";
        class  Demo1 extends Thread{

            @Override
            public void run() {
                System.out.println(a + b+"\r\n"+Thread.currentThread().getName());
                ;
            }
        }
        new Demo1().start();
    }

    /**
     * No.2 内部类的变种:匿名内部类
     */
    public void useThreadRunMethod2(){
        String b = "bbb";
        new Thread(new Runnable(){
            @Override
            public void run() {
                System.out.println(a + b+"\r\n"+Thread.currentThread().getName());
            }
        }).start();
    }

    /**
     * 测试 NO.1 & NO.2
     */
    public static void a(){
        System.out.println(Thread.currentThread().getName());
        new InnerClassTest().useThreadRunMethod1();
        new InnerClassTest().useThreadRunMethod2();
    }


    /**
     * NO.3 使用内部类可以变相支持多继承
     */
    public static void mutiExtends(){
        class Demo1{
            public void test1(){
                System.out.println("我是Demo1类的方法");
            }
        }

        class  Demo2{
            public void test2(){
                System.out.println("我是Demo2类的方法");
            }
        }

        class Demo3 extends Demo1{
            class Demo4 extends Demo2{
                public void useDemo3Method(){
                    super.test2();
                }
            }
            public void test3(){
                super.test1();
                new Demo4().test2();
            }
        }
        new Demo3().test3();
    }

    interface Calls {
        /**
         * 回调函数方法
         */
        void callback(String a);
    }


    /**
     * No.4 使用匿名内部类来实现方法回调
     */
    public static void callBackMethod(){
        class Demo{
            private String a = "ss";
            public void test(Calls calls){
                calls.callback(a);
            }
        }

        new Demo().test(a -> {
            System.out.println(a+"调用者编写方法实现");
        });

    }


    public static void main(String[] args) {
        // 还有一个是可以区分继承和实现的方法名一致问题
    }




}
