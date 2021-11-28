package com.wangwenjun.concurrent.chapter07;

import java.util.concurrent.TimeUnit;

/**
 * 通过Runtime为java线程注入钩子线程测试
 * @author admin
 */
public class ThreadHook {
    public static void main(String[] args) {
        // 注意看addShutdownHook,jvm进程收到退出信号后会调用这个方法 (注意，如果是kill -9 pid 关闭进程，则jvm会立即关闭,不会执行钩子线程)
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                System.out.println("The hook thread 2 is running.");
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("The program will exit.");
        }));

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                System.out.println("The hook thread 2 is running.");
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("The hook thread 2 will exit.");
        }));
        System.out.println("The program will is stopping.");
    }
}
