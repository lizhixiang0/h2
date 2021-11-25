package com.wangwenjun.concurrent.chapter02;


import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadConstruction {

    /**
     * 测试stackSize的作用
     */
    private static void test_stack_size() {
        int stackSize = 100000;
        ThreadGroup group = new ThreadGroup("TestGroup");
        Runnable runnable = new Runnable() {
            final int MAX = Integer.MAX_VALUE;

            @Override
            public void run() {

                int i = 0;
                recurse(i);
            }

            private void recurse(int i) {
                System.out.println(i);
                if (i < MAX) {
                    recurse(i + 1);
                }
            }
        };
        Thread thread = new Thread(group, runnable, "Test", stackSize);
        thread.start();
    }

    /**
     * 测试默认情况下jvm栈内存 支持创建多少线程
     *
     * 使用下 JVisualVM
     */
    public static void test_thread_count (){
        final  AtomicInteger counter = new AtomicInteger(0);
        try {
            while (true) {
                new Thread(()->{
                    try {
                        System.out.println("The " + counter.getAndIncrement() + " thread be created.");
                        TimeUnit.MINUTES.sleep(10);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }).start();
            }
        } catch (Throwable e) {
            System.out.println("failed At=>" + counter.get());
            System.exit(1);
        }
    }

    /**
     * 如果JVM中只剩下守护线程,则JVM进程会自动退出 ! 反之,即使main线程执行结束,还存在非守护线程,jvm进行会等待它执行完
     *
     * 子线程t中创建了一个持续运行的守护线程
     * @throws InterruptedException
     */
    public static void test_daemon_thread() throws InterruptedException {
        Thread t = new Thread(() ->
        {
            Thread innerThread = new Thread(() -> {
                // 持续运行
                while (true) {
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            });

            innerThread.setDaemon(true);  // 设置innerThread为守护线程 (如果父线程是守护线程，则子线程默认是守护线程)
            innerThread.start();
        });
        t.start();
        TimeUnit.MILLISECONDS.sleep(20);
        System.out.println(t.getState());
        System.out.println("main线程执行结束");
    }

    public static void main(String[] args) throws InterruptedException {
        test_daemon_thread();
    }
}
