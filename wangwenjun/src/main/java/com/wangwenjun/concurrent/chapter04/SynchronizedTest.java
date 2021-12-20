package com.wangwenjun.concurrent.chapter04;

import java.util.concurrent.TimeUnit;

/**
 * 简单使用下synchronized
 * @author admin
 */
public class SynchronizedTest {
    /**
     * MUTEX对象头上有引用指向一个monitor对象 ,另外还有一些锁标识位用来记录当前是什么锁,以及哪个线程占用了锁
     * monitor对象中有个计数器，默认为0,线程每进入一次就+1 ,如果是已经拥有该monitor的线程重入，那就再+1
     * monitor对象中还有一个block set ,阻塞住的线程会存在这个里面
     */
    private final static Object MUTEX = new Object();

    public void accessResource() {
        synchronized (MUTEX) {
            try
            {
                TimeUnit.MINUTES.sleep(10);
            } catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        }
    }
    /**
     * 执行后使用JConsole看下线程状态
     * 使用jstack打印下thread dump
     * 使用javap -c  xx 对类文件进行反编译 , 会看到一对monitor enter & exit
     * @param args
     */
    public static void main(String[] args)
    {
        final SynchronizedTest synchronizedTest = new SynchronizedTest();
        for (int i = 0; i < 5; i++)
        {
            new Thread(synchronizedTest::accessResource).start();
        }
    }
}