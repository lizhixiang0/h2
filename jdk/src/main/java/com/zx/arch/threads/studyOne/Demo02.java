package com.zx.arch.threads.studyOne;

import java.util.concurrent.atomic.AtomicLong;

/**
 * @author lizx
 * @date 2020/12/06
 * @description 介绍线程安全的类 - - - - -》》》》 原子类   保证原子操作
 * @blog 介绍 CAS https://www.cnblogs.com/programerlrc/articles/4936369.html
 **/
public class Demo02 {
    private static final AtomicLong a = new AtomicLong();

    public static void main(String[] args) {
        System.out.println(a.incrementAndGet());
    }
}
