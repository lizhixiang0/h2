package com.wangwenjun.concurrent.chapter08;

/**
 * 任务容器
 * @author admin
 */
public interface RunnableQueue {

    void offer(Runnable runnable);

    Runnable take() throws InterruptedException;

    int size();
}
