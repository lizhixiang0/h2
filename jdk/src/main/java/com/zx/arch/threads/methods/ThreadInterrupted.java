package com.zx.arch.threads.methods;

import java.util.concurrent.TimeUnit;

/**
 * @author lizx
 * @date 2021/10/25
 * @since
 **/
public class ThreadInterrupted {
    public static void main(String[] args) {
        // 修改线程打断标识,线程的某些方法会响应打断，例如sleep，会抛异常
        Thread.currentThread().interrupt();
        // 判断线程是否被打断过
        System.out.println("is interrupted? " + Thread.currentThread().isInterrupted());
        // 判断当前线程是否被打断过,打断过则恢复
        System.out.println("is interrupted? " + Thread.interrupted());

        System.out.println("is interrupted? " + Thread.currentThread().isInterrupted());

        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {

            System.out.println("interrupted");
        }
    }
}
