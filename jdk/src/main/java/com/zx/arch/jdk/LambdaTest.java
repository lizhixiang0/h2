package com.zx.arch.jdk;


import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * @author lizx
 * @since 1.0.0
 * @description lambda 表达式学习
 * @description "https://www.cnblogs.com/haixiang/p/11029639.html
 **/
public class LambdaTest<T> {

    private<T> T a(Supplier<T> supplier){
        return supplier.get();
    }

    private<T> T b(Consumer<T> consumer){
        return null;
    }

    /**
     * 通过接口Supplier来更好的理解lambda
     * 第一个理解,lambda表达式是一种思想！！他的核心思想就是将函数作为参数传递出去！而函数则是接口里抽象方法的实现！
     * 比如我在a方法中将Supplier作为参数类型,打开Supplier接口发现其就一个get抽象方法,则入参时传递的函数就是这个get()方法！
     * 区别于匿名内部类，lambda的语法显得更加简洁！思想也更先进,
     * 因为我们观察接口里的get()方法，发现其目的是为了获得一个对象，获得对象是我们的最终目的！
     * 所以我们看到了两种语法，最终目的都是为了满足接口的需求，获得一个对象。
     * “::” 和 “()->”
     */
    public void test(){
        //匿名内部类
        String s = a(new Supplier<String>() {
            @Override
            public String get() {
                return "ss";
            }
        });

        //lambda表达式
        String s1 = a(()->"ss");

        //::方式
        a(UUID::randomUUID);
    }
}
