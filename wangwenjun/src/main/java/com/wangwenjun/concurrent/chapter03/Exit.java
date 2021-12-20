package com.wangwenjun.concurrent.chapter03;

import java.util.concurrent.TimeUnit;

/**
 * 线程关闭方法
 *          一般线程结束生命周期就会正常结束,需要我们控制关闭的线程都是体内有死循环,我们需要做的就是打断死循环
 *          比如可以利用中断标记或者volatile属性来打断循环！
 *
 *
 * @author admin
 */
public class Exit {

    public static void test_thread_normal_exit_first() throws InterruptedException {

        Thread t = new Thread(() -> {
            System.out.println("I will start work");
            while(true) {
                // working...
                // 使用能够响应中断的方法,一旦检测到中断标记则抛出异常从而跳过循环，然后线程结束生命周期,正常结束
                try {
                    TimeUnit.SECONDS.sleep(5);
                } catch (InterruptedException e) {
                    break;
                }
            }
            System.out.println("I will be exiting.");
        });
        t.start();
        TimeUnit.SECONDS.sleep(5);
        System.out.println("System will be shutdown.");
        // 打断t线程
        t.interrupt();
    }

    static class Task extends Thread {

        private volatile boolean closed = false;

        @Override
        public void run() {
            System.out.println("I will start work");
            while (!closed && !isInterrupted()) {
                // working...
            }
            System.out.println("I will be exiting.");
        }

        public void close() {
            this.closed = true;
            this.interrupt();
        }
    }

    public static void test_thread_normal_exit_second() throws InterruptedException {
        Task t = new Task();
        t.start();
        TimeUnit.SECONDS.sleep(1);
        System.out.println("System will be shutdown.");
        t.close();
    }

    public static void main(String[] args) throws InterruptedException {
        test_thread_normal_exit_second();
    }
}
