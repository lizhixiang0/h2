package com.wangwenjun.concurrent.chapter05.custom_lock;

import java.util.List;
import java.util.concurrent.TimeoutException;

public interface Lock
{

    void lock() throws InterruptedException;

    void lock(long mills) throws InterruptedException, TimeoutException;

    void unlock();

    List<Thread> getBlockedThreads();
}
