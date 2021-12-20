package com.wangwenjun.concurrent.chapter03;

import java.util.concurrent.TimeUnit;

/**
 * 很多方法会使线程阻塞,但是这些方法都响应interrupt,换句话说,interrupt可以打断线程的阻塞状态，被打断阻塞的线程会抛出InterruptedException异常并且擦除中断标记
 * @author admin
 */
public class Interrupt {

    public static void test_interrupt() throws InterruptedException {
        Thread thread = new Thread(() -> {
            try {
                // ready to sleep 1 minute
                TimeUnit.MINUTES.sleep(1);
            } catch (InterruptedException e) {
                System.out.println("Oh, i am be interrupted.");
            }
        });
        thread.start();
        // short block and make sure thread is started.
        TimeUnit.MILLISECONDS.sleep(2);
        // 主线程调用阻塞线程的interrupt方法
        thread.interrupt();
    }

    /**
     * 线程中有个interrupt标记,默认是未中断,调用interrupt方法会将该标记改为中断标记,可中断方法都可以检测到中断标记,抛出异常并擦除中断标记
     */
    public static void test_is_interrupted() {
        System.out.println("Main thread is interrupted? " + Thread.currentThread().isInterrupted());
        // 修改为中断标记
        Thread.currentThread().interrupt();
        System.out.println("Main thread is interrupted? " + Thread.currentThread().isInterrupted());

        try {
            // 检测到中断标记,抛出异常并擦除中断标记
            TimeUnit.MINUTES.sleep(1);
        } catch (InterruptedException e) {
            System.out.println("I am interrupted.");
        }

        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            System.out.println("I  am interrupted again.");
        }
    }

    /**
     * interrupted方法除了可以判断线程是否中断，并且恢复interrupt标记位
     */
    public static void test_interrupted() throws InterruptedException {
        Thread thread = new Thread(() -> {
            // ... false true ... false
            while (true){
                System.out.println(Thread.interrupted());
            }
        });
        thread.setDaemon(true);
        thread.start();

        //shortly block make sure the thread is started.
        TimeUnit.NANOSECONDS.sleep(1);
        thread.interrupt();
    }


    public static void main(String[] args) throws InterruptedException {
        test_interrupted();
    }
}
