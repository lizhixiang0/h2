package com.wangwenjun.concurrent.chapter04;

/**
 * 体会交叉锁导致的线程死锁
 * @author admin
 */
public class DeadLock {

    private final Object MUTEX_READ = new Object();
    private final Object MUTEX_WRITE = new Object();

    public void read() {
        synchronized (MUTEX_READ) {
            synchronized (MUTEX_WRITE) {
            }
        }
    }


    public void write() {
        synchronized (MUTEX_WRITE) {
            synchronized (MUTEX_READ) {
            }

        }
    }

    /**
     * 交叉死锁不是一调用就会出现,必须是两个线程同时取得第一把,尝试获取第二把锁的时刻会出现死锁
     * 所以这里用死循环,一直调用两个方法！
     */
    public void test_cross_dead_lock(){
        final DeadLock deadLock = new DeadLock();
        new Thread(() -> {
            while (true) {
                deadLock.read();
            }
        }, "READ-THREAD").start();

        new Thread(() -> {
            while (true) {
                deadLock.write();
            }
        }, "WRITE-THREAD").start();
    }

    public static void main(String[] args) {
        // 使用jstack ,会出现 Thread.State: BLOCKED 字样
        new DeadLock().test_cross_dead_lock();
    }
}
