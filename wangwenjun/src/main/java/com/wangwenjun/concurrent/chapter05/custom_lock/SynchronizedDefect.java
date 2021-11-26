package com.wangwenjun.concurrent.chapter05.custom_lock;

import java.util.concurrent.TimeUnit;


/**
 * Synchronized的缺点：
 *      1、无法控制加锁,比如尝试加锁，超过一段时间获取不到就放弃，这个功能无法实现
 *      2、阻塞无法响应中断
 * @author admin
 */
public class SynchronizedDefect {

    public synchronized void syncMethod()
    {
        try {
            TimeUnit.HOURS.sleep(1);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws InterruptedException {
        SynchronizedDefect defect = new SynchronizedDefect();
        Thread t1 = new Thread(defect::syncMethod, "T1");
        //make sure the t1 started.
        t1.start();
        TimeUnit.MILLISECONDS.sleep(2);

        Thread t2 = new Thread(defect::syncMethod, "T2");
        t2.start();
        //make sure the t2 started.
        TimeUnit.MILLISECONDS.sleep(2);
        t2.interrupt();
        System.out.println(t2.isInterrupted());
        System.out.println(t2.getState());
    }
}
