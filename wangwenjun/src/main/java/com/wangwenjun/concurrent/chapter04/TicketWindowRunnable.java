package com.wangwenjun.concurrent.chapter04;

/**
 *
 * 并发三大要素：可见性、原子性、有序性
 *
 * 原子性：多个操作,必須一起執行完，不可以被打断
 * 可見性：一个线程对共享变量的修改对其他线程可见
 * 有序性：代码按照程序员书写的顺序执行，例子：双重校验锁实现单例
 *
 * 大厅叫号系统如果不加锁,会出现三种异常
 *  1、多叫号，比如只有500张票，叫到501张 ;  未满足原子执行
 *  2、少叫号，比如第400张票跳过去了 ; 未满足原子执行
 *  3、重复叫号，第400张票叫了两次  ;  未保证共享变量可见性
 *
 * @author admin
 */
public class TicketWindowRunnable implements Runnable {

    private int index = 1;
    /**
     * 多线程共享变量
     */
    private final static int MAX = 500;

    /**
     * 多线程共享锁
     */
    private final static Object MUTEX = new Object();

    @Override
    public void run() {
        synchronized (MUTEX) {
            // 1、判断
            while (index <= MAX) {
                // 2、叫号
                // 3、num++
                System.out.println(Thread.currentThread() + " 的号码是:" + index++);
            }
        }
    }

    public static void main(String[] args) {
        final TicketWindowRunnable task = new TicketWindowRunnable();

        Thread windowThread1 = new Thread(task, "一号窗口");
        Thread windowThread2 = new Thread(task, "二号窗口");
        Thread windowThread3 = new Thread(task, "三号窗口");
        Thread windowThread4 = new Thread(task, "四号窗口");
        windowThread1.start();
        windowThread2.start();
        windowThread3.start();
        windowThread4.start();
    }
}
