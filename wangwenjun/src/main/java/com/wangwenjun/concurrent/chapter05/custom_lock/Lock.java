package com.wangwenjun.concurrent.chapter05.custom_lock;

import java.util.List;
import java.util.concurrent.TimeoutException;

public interface Lock
{
    /**
     * 获取锁资源
     * @throws InterruptedException
     */
    void lock() throws InterruptedException;

    /**
     * 一段时间内获取不到锁资源则放弃
     * @param mills
     * @throws InterruptedException
     * @throws TimeoutException
     */
    void lock(long mills) throws InterruptedException, TimeoutException;

    /**
     * 释放锁资源
     */
    void unlock();

    /**
     * 获取所有阻塞的线程
     * @return
     */
    List<Thread> getBlockedThreads();
}
