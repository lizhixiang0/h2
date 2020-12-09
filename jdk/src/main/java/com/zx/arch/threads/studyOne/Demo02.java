package com.zx.arch.threads.studyOne;


import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author lizx
 * @date 2020/12/06
 * @description 介绍线程安全的类 - - - - -》》》》 原子类   保证原子操作
 * @blog 介绍 CAS https://www.cnblogs.com/programerlrc/articles/4936369.html
 **/
public class Demo02 {
    /**
     * 表示该属性一旦被初始化便不可改变，
     * 这里不可改变的意思     对基本类型来说是其值不可变，而对对象属性来说其引用不可再变
     */
    private static final AtomicLong a = new AtomicLong();

    private static final AtomicReference<Long> b = new AtomicReference<>();


    public static void main(String[] args) {
        System.out.println(a.incrementAndGet());
    }
}
