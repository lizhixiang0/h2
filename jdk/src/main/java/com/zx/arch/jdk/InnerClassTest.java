package com.zx.arch.jdk;


/**
 * @author lizx
 * @since 1.0.0
 * @description 测试内部类的作用,首先，用内部类是因为内部类与所在外部类有一定的关系，往往只有该外部类调用此内部类。所以没有必要专门用一个Java文件存放这个类
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
     * No.2 内部类的变种:匿名内部类  ，传递的是一个对象，直接生成类文件
     */
    public void useThreadRunMethod2(){
        String b = "bbb";
        new Thread(new Runnable(){
            @Override
            public void run() {
                System.out.println(a + b+"\r\n"+Thread.currentThread().getName());
            }
        }).start();

        /**
         * Lambda表达式，传递的是一个函数.会在第一次调用时动态生成类文件
         * 拓展:Lambda表达式和匿名内部类的区别
         * "https://www.cnblogs.com/cht-/p/11897887.html
         * "https://www.cnblogs.com/alinainai/p/11112455.html
         * 注意：Lambda 规定接口中只能有一个需要被实现的方法，不是规定接口中只能有一个方法
         */
        new Thread(()->{
            System.out.println(a + b+"\r\n"+Thread.currentThread().getName());
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
        String a = "ss";
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
     *       我的理解就是不需要改变原始代码，调用者实现接口方法
     */
    public static void callBackMethod(){
        class Demo{
            private String a = "ss";
            public void test(Calls calls){
                calls.callback(a);
            }
        }

        /**
         *
         */
        new Demo().test(a -> {
            System.out.println(a+"调用者编写方法实现");
        });

    }

    /**
     * 还有内部接口也很牛逼,见过一个大神用过
     * 好处：内部接口可以使用外部类的属性！！！并且可以根据不同的情况定制所需要的类
     */
    public static void testInnerInterface(){

    }

    /**
     * 静态内部类的作用
     */
    public static void testInner(){
        /**
         * 内部类和静态修饰符static
         * (1）首先，用内部类是因为内部类与所在外部类有一定的关系，往往只有该外部类调用此内部类。所以没有必要专门用一个Java文件存放这个类。
         * (2）静态都是用来修饰类的内部成员的。比如静态方法，静态成员变量，静态常量。它唯一的作用就是随着类的加载（而不是随着对象的产生）而产生，以致可以用类名+静态成员名直接获得。
         * 这样静态内部类就可以理解了，因为这个类没有必要单独存放一个文件，它一般来说只被所在外部类使用。并且它可以直接被用 外部类名+内部类名 获得。
         */
    }

    public static void main(String[] args) {
        // 还有一个是可以区分继承和实现的方法名一致问题
    }




}
