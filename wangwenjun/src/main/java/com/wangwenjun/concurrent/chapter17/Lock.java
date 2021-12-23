package com.wangwenjun.concurrent.chapter17;

/**
 * 定义锁的基本行为,加锁和解锁
 * @author admin
 */
public interface Lock {
    /**
     * 获取锁,获取不到则阻塞
     * @throws InterruptedException
     */
    void lock() throws InterruptedException;

    /**
     * 释放锁
     */
    void unlock();
}