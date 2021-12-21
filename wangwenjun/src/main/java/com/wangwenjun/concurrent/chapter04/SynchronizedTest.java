package com.wangwenjun.concurrent.chapter04;

import java.util.concurrent.TimeUnit;

/**
 * 简单使用下synchronized
 *
 * 1、锁粗化
 * 2、锁升级
 * 3、锁消除
 *
 * @author admin
 */
public class SynchronizedTest {
    /**
     * MUTEX对象头上有引用指向一个monitor对象 ,另外还有一些锁标识位用来记录当前是什么锁,以及哪个线程占用了锁
     * monitor对象中有个计数器，默认为0,线程每进入一次就+1 ,如果是已经拥有该monitor的线程重入，那就再+1
     * monitor对象中还有一个block set ,阻塞住的线程会存在这个里面
     *
     * 监视器锁本质又是依赖于底层的操作系统的Mutex Lock来实现的,使用Mutex Lock需要将当前线程挂起并从用户态切换到内核态来执行
     * 在JVM手册中，synchronized可见性也有两层语义。
     *
     * （1）在线程加锁时，必须从主内存获取最新值。
     * （2）在线程解锁时，必须把共享变量刷新到主内存。
     *
     */
    private final static Object MUTEX = new Object();

    public void accessResource() {
        synchronized (MUTEX) {
            try {
                TimeUnit.MINUTES.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     *   执行后使用JConsole看下线程状态
     *   使用jstack打印下thread dump
     *   使用javap -c  xx 对类文件进行反编译 , 会看到一对monitor enter & exit
     */
    public void testSynchronized(){
        final SynchronizedTest synchronizedTest = new SynchronizedTest();
        for (int i = 0; i < 5; i++) {
            new Thread(synchronizedTest::accessResource).start();
        }
    }



    /**
     * 锁粗化
     * 如果一系列的连续操作都对同一个对象反复加锁和解锁（比如加锁操作是出现在循环体中）
     * 由于频繁地进行互斥同步操作也会导致不必要的性能损耗。
     * 虚拟机探测到有这样一串零碎的操作都对同一个对象加锁,将会把加锁同步的范围扩展（膨胀）到整个操作序列的外部（由多次加锁编程只加锁一次）
     *
     * 本来是：
     *      for (int i = 0; i < 10000; i++) {
     *          synchronized(){
     *
     *          }
     *      }
     * 膨胀后：
     *      synchronized(){
     *         for (int i = 0; i < 10000; i++) {
     *
     *         }
     *      }
     * https://blog.csdn.net/mingyuli/article/details/121054466
     */
    public static void LockCoarsening() throws InterruptedException {
        class Task implements Runnable {
            private int count = 0;

            @Override
            public void run() {
                for (int i = 0; i < 10000; i++) {
                    count++;
                    // 如果不加System.out.println,那误差会很大,加了System.out.println误差会很小，但还是会有! 因为锁膨胀有个过程,不是一下次膨胀!
                    System.out.println(Thread.currentThread().getName());
                }
            }
        }
        Task task = new Task();
        Thread t1 = new Thread(task, "t1");
        Thread t2 = new Thread(task, "t2");
        t1.start();
        t2.start();
        t1.join();
        t2.join();
        System.out.println(task.count);
    }

    /**
     * 锁消除
     *
     * StringBuilder对象的append()操作是同步操作,但是sb对象是函数内部的局部变量，进作用于方法内部，不可能逃逸出该方法！
     * LockElimination()方法时，都会创建不同的sb对象,所以此时的append操作使用同步操作，完全是浪费系统资源
     *
     * 这时我们可以通过编译器将其优化，将锁消除
     *  -server -XX:+DoEscapeAnalysis -XX:+EliminateLocks   （运行在server模式（server模式会比client模式作更多的优化）并且开启逃逸分析和锁消除 ）
     *  idea如何配置JVM参数：https://www.cnblogs.com/lihaoyang/p/12424633.html
     *
     *  注：这也是为什么我们推荐使用StringBuilder
     *  https://blog.csdn.net/mingyuli/article/details/121054466
     *
     */
    public static void LockElimination(){
        StringBuffer sb = new StringBuffer();
        long tsStart = System.currentTimeMillis();
        for (int i = 0; i < 50000000; i++) {
            sb.append("1");
            sb.append("2");
        }
        System.out.println("一共耗费：" + (System.currentTimeMillis() - tsStart) + " ms");
    }


    /**

     * @param args
     */
    public static void main(String[] args) throws InterruptedException {
        LockElimination();
    }
}