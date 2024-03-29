package com.wangwenjun.concurrent.chapter08;

import java.util.concurrent.atomic.AtomicInteger;

/**
 *  线程工厂规范线程名和线程组
 * @author admin
 */
public interface ThreadFactory {
    Thread createThread(Runnable runnable);

    class DefaultThreadFactory implements ThreadFactory {

        private static final AtomicInteger GROUP_COUNTER = new AtomicInteger(1);

        private static final ThreadGroup group = new ThreadGroup("MyThreadPool-" + GROUP_COUNTER.getAndDecrement());

        private static final AtomicInteger COUNTER = new AtomicInteger(0);

        @Override
        public Thread createThread(Runnable runnable) {
            return new Thread(group, runnable, "thread-pool-" + COUNTER.getAndDecrement());
        }
    }
}
