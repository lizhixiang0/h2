package com.wangwenjun.concurrent.chapter12;

import java.util.concurrent.TimeUnit;

/**
 * 简单测试 volatile
 * @author admin
 */
public class VolatileFoo {

    private  static int init_value = 0;

    /**
     * 测试可见性
     * 因为cpu空闲时会从主存中读取,所以这里不行，即使init_value不加volatile,运行一段时间后,线程1还是能读到修改后的init_value
     */
    public static void test_volatile_one(){
        /**
         * 线程 1 不断判断并打印 init_value
         */
        new Thread(() -> {
            while (init_value == 0) {
                System.out.printf("The init_value is updated to [%d]\n", init_value);
            }
        }, "Reader").start();


        /**
         * 线程 2 将init_value 改为 1 , 看看线程1是否能读到
         */
        new Thread(() -> {
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.printf("The init_value will be changed to [%d]\n", ++init_value);
        }, "Updater").start();
    }

    /**
     * 测试可见性
     * https://www.jianshu.com/p/ca5552befd2a
     */
    public static void test_volatile_two(){
        new Thread(() -> {
            int localValue = init_value;
            while (localValue == 0) {
                // 检测 init_value 的变化,这里检测不到，因为一直读的缓存中的init_value
                // 但是如果while循环中加上一句System.out.println() ,则会检测到，因为System.out.println中有加锁操作，加锁会导致从主存读取数据
                if (init_value != localValue) {
                    System.out.printf("The init_value is updated to %d\n", init_value);
                    localValue = init_value;
                }
            }
        }, "Reader").start();

        new Thread(() -> {
            int localValue = init_value;
            while (localValue == 0) {
                // 第一步：get localValue
                // 第二步：localValue +1    必须在本地内存执行完 +1 操作
                // 第三步：set localValue   写入主内存
                ++localValue;
                // 这里用了printf,线程1就检测不到,为什么?
                 System.out.printf("The init_value will be changed to " + localValue + "\n");
                // 第一步：get localValue (如果工作内存没有则从主内存获取)
                // 第二步：在工作内存中修改init_value为localValue，最后将init_value写入主内存
                init_value = localValue;
            }
            System.out.println("The init_value has be changed to "+ init_value);
        }, "Updater").start();
    }


    public static void main(String[] args) {
        test_volatile_two();
    }
}
