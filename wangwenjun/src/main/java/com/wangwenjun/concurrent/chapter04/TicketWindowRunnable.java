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
 *  1、多叫号，比如只有500张票，叫到501张 ;  未满足原子执行   （两个线程都判断499满足条件,其中一个执行到500写入主内存,cpu切换到另一个线程从主线程读到500,执行到+1 ,叫号501）
 *  2、少叫号，比如第499张票跳过去了 ; 未满足原子执行        （cpu调度线程或者时间片切换导致,某个线程将票数+1写入主内存,还未叫票,cpu切换到另一个线程去了）
 *  3、重复叫号，第400张票叫了两次  ;  未保证共享变量可见性  (多核cpu同时读到399,核1执行399+1写入主内存,核2此时不会从主内存读取（没有发生切换，工作内存没有失效），继续399+1）
 *
 *  需要搞明白,变量什么时候从线程空间写入主内存！什么时候又从主内存读入内存空间？

    1、只有变量修改了就得从线程空间写入主内存！
 *  2、工作内存失效的时候。工作内存就会重新加载主内存的变量
 *     三种情况工作内存的变量会失效
 *          1、线程中释放锁时
 *          2、线程切换时
 *          3、线程sleep休眠，IO操作  (此类cpu空闲的时)
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

    /**
     * 这个方法需要加锁吗？run方法中加锁可以理解,因为要保证index的改变被所有线程看到
     *
     * @return
     */
    private int read(){
        return index;
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
