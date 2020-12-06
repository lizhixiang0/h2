package com.zx.arch.threads.studyOne;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;

/**
 * @author lizx
 * @date 2020/12/01
 * @description 一个不安全的多线程！
 *              原先我一直觉得成员变量不会导致线程不安全！只有类变量会导致线程不安全！
 *              但是不是，对象一旦实例化了,在多线程环境下操纵堆中的实例变量！
 *              这个实例变量引用地址是同一个！所以会导致线程不安全。
 *              下面是实例
 *
 * @note    注意：下面写到了一些注解，主要作用是提醒开发人员。
 *
 *
 *
 *
 **/
//表示这是一个线程安全的类
@ThreadSafe
public class Demo01 {
    //表示必须拿到本对象的锁才能访问本变量，我是不懂外国人咋想的，为啥叫拿到锁，应该叫拿到钥匙
    @GuardedBy("this")
    private int value ;

    //加了个锁
    public synchronized  int getValue(){
        //等待时间用来增加线程争抢的几率,如果不加上还是比较难看到不安全情况的
        //所以工作中尤其小心那种一堆线程一起排队等待的情况，很容易就会出现线程不安全的情况
        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return value++;
    }

    public static void main(String[] args) {

        Demo01 demo01 = new Demo01();

            new Thread(() -> {
                while (true){
                    System.out.println(Thread.currentThread().getName() +"线程"+demo01.getValue());
                }
            }).start();

            new Thread(() -> {
                while(true){
                    System.out.println(Thread.currentThread().getName() +"线程"+demo01.getValue());
                }
            }).start();

    }
}
