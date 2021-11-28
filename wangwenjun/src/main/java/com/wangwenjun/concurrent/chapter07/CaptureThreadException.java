package com.wangwenjun.concurrent.chapter07;

import java.util.concurrent.TimeUnit;

/**
 * Java的异常(包括Exception和Error)分为 可查的异常（checked exceptions）和不可查的异常（unchecked exceptions） 。
 * 可查异常（编译器要求必须处置的异常）：
 *                  正确的程序在运行中，很容易出现的、情理可容的异常状况 。
 *                  可查异常虽然是异常状况，但在一定程度上它的发生是可以预计的，而且一旦发生这种异常 状况，就必须采取某种方式进行处理。
 *                  除了RuntimeException及其子类以外，其他的Exception类及其子类都属于可查异常。这种异常的特点是Java编译器会检查它，也就是说，当程序中可能出现这类异常，要么用try-catch语句捕获它，要么用throws子句声明抛出它，否则编译不会通过。
 * 不可查异常(编译器不要求强制处置的异常):
 *               包括运行时异常（RuntimeException与其子类）和错误（Error）。
 *
 *  在普通的单线程程序中，捕获异常只需要通过try ... catch ... finally ...代码块就可以了,而并发情况下直接在父线程启动子线程的地方try ... catch来捕捉子线程的异常则不行
 *  首先，run方法的完整签名，因为没有标识throws语句，所以方法是不会抛出checked异常的 ！
 *  另外，RuntimeException这样的unchecked异常，由于新线程由JVM进行调度执行，如果发生了异常，也不会通知到父线程
 *
 *  有三种获得子线程异常的方法：
 *      1、子线程内部try... catch...，通过日志记录
 *      2、为线程设置未捕获异常处理器UncaughtExceptionHandler，线程在出现运行时异常时会回调UncaughtExceptionHandler的uncaughtException方法
 *      3、通过Future的get方法捕获异常
 *      https://www.cnblogs.com/jpfss/p/10272066.html
 *
 *  下面使用的是第二种方法
 *
 * @author admin
 */
public class CaptureThreadException
{

    public static void main(String[] args) {
        /**
         * 使用lambda表达式创建一个UncaughtExceptionHandler对象作为参数，其中实现的就是回调方法，t是线程实例,e是异常
         */
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            System.out.println(t.getName() + " occur exception");
            e.printStackTrace();
        });

        final Thread thread = new Thread(() -> {
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException e) {
            }
            //here will throw unchecked exception.
            System.out.println(1 / 0);
        }, "Test-Thread");

        thread.start();
    }
}
