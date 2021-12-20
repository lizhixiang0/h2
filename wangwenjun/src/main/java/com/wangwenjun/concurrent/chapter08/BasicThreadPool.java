package com.wangwenjun.concurrent.chapter08;

import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.TimeUnit;

/**
 * 利用wait和notify來控制，綫程一創建就start,不断从LinkedRunnableQueue中获取task,如果获取到就执行，获取不到就wait !
 * 我觉得这个线程池的瓶颈在于获取take方法,这个方法是加锁的,效率不高
 *
 * 但是这个线程池教会了我很多东西
 * 首先、所有能抽离出去的行为都进行了分类并组织到不同接口下,另外作者利用while来实现定时任务让我眼界大开，
 * 另外作者在shutdown线程池时调用了interrupt(),然后判断时都加了isInterrupted()。这里了解一下。
 *
 * 最后，作者时通过继承Thread,然后在构造方法中调用init方法，然后init方法主动去调用start方法来启动管理线程的！（管理线程用来管理线程数量）
 * 思路很好了，但是作者说更好的应该是使用组合模式，因为BasicThreadPool继承了Thread，实现的run方法是个public方法,会暴露给调用者，这样不安全！
 * 那么采用组合模式怎么搞？？
 *
 * 内部实现一个私有线程，把管理线程的逻辑交给这个私有线程去做！
 *
 *
 *
 * @author admin
 */
public class BasicThreadPool  implements ThreadPool {

    private final int initSize;

    private final int maxSize;

    private final int coreSize;

    private int activeCount;

    private final ThreadFactory threadFactory;

    private final RunnableQueue runnableQueue;

    private volatile boolean isShutdown = false;

    private final Queue<ThreadTask> threadQueue = new ArrayDeque<>();

    private final static DenyPolicy DEFAULT_DENY_POLICY = new DenyPolicy.DiscardDenyPolicy();

    private final static ThreadFactory DEFAULT_THREAD_FACTORY = new ThreadFactory.DefaultThreadFactory();

    private final long keepAliveTime;

    private final TimeUnit timeUnit;

    private final Thread manageThread;


    public BasicThreadPool(int initSize, int maxSize, int coreSize, int queueSize) {
        this(initSize, maxSize, coreSize, DEFAULT_THREAD_FACTORY, queueSize, DEFAULT_DENY_POLICY, 10, TimeUnit.SECONDS);
    }

    public BasicThreadPool(int initSize, int maxSize, int coreSize,
                           ThreadFactory threadFactory, int queueSize,
                           DenyPolicy denyPolicy, long keepAliveTime, TimeUnit timeUnit) {
        this.initSize = initSize;
        this.maxSize = maxSize;
        this.coreSize = coreSize;
        this.threadFactory = threadFactory;
        this.runnableQueue = new LinkedRunnableQueue(queueSize, denyPolicy, this);
        this.keepAliveTime = keepAliveTime;
        this.timeUnit = timeUnit;
        this.manageThread = new ManageThread();
        this.init();
    }

    /**
     * 管理线程
     *
     * 1、线程池已经关闭，则管理线程也关闭
     * 2、任务数目大于0且活动线程小于核心线程数，则创建线程
     * 3、任务数目大于0且活动线程小于最大线程数，则创建线程
     * 4、任务数目等于0且活动线程小于核心线程数，则销毁线程
     *
     */
   private class ManageThread extends Thread{
        @Override
        public void run() {
            while (!isShutdown && !isInterrupted()) {
                try {
                    timeUnit.sleep(keepAliveTime);
                } catch (InterruptedException e) {
                    isShutdown = true;
                    break;
                }

                synchronized (this) {
                    if (isShutdown) {
                        break;
                    }
                    if (runnableQueue.size() > 0 && activeCount < coreSize) {
                        for (int i = initSize; i < coreSize; i++)
                        {
                            System.out.println("--create");
                            newThread();
                        }
                        continue;
                    }

                    if (runnableQueue.size() > 0 && activeCount < maxSize) {
                        for (int i = coreSize; i < maxSize; i++) {
                            newThread();
                        }
                    }

                    if (runnableQueue.size() == 0 && activeCount > coreSize) {
                        for (int i = coreSize; i < activeCount; i++) {
                            removeThread();
                        }
                    }
                }
            }
        }
    }

    /**
     * 启动管理线程,并且启动最低数目的线程
     */
    private void init() {
        manageThread.start();
        for (int i = 0; i < initSize; i++) {
            newThread();
        }
    }


    @Override
    public void execute(Runnable runnable) {
        if (this.isShutdown) {
            throw new IllegalStateException("The thread pool is destroy");
        }
        this.runnableQueue.offer(runnable);
    }

    /**
     * 创建新线程的逻辑
     *
     *
     */
    private void newThread() {
        // 先创建核心任务，不断从任务池获取任务进行执行
        InternalTask internalTask = new InternalTask(runnableQueue);
        // 创建线程
        Thread thread = this.threadFactory.createThread(internalTask);
        // 创建包装线程对象ThreadTask，用来控制关闭internalTask  (这一步没必要这样吧，直接工厂生成ThreadTask我看更好)
        ThreadTask threadTask = new ThreadTask(thread, internalTask);
        threadQueue.offer(threadTask);
        this.activeCount++;
        thread.start();
    }

    private void removeThread() {
        ThreadTask threadTask = threadQueue.remove();
        threadTask.internalTask.stop();
        this.activeCount--;
    }

    /**
     * shutdown的逻辑是
     */
    @Override
    public void shutdown() {
        synchronized (this) {
            if (isShutdown) {
                return;
            }
            isShutdown = true;
            threadQueue.forEach(threadTask -> {
                threadTask.internalTask.stop();
                threadTask.thread.interrupt();
            });
            manageThread.interrupt();
        }
    }

    @Override
    public int getInitSize() {
        if (isShutdown) {
            throw new IllegalStateException("The thread pool is destroy");
        }
        return this.initSize;
    }

    @Override
    public int getMaxSize() {
        if (isShutdown) {
            throw new IllegalStateException("The thread pool is destroy");
        }
        return this.maxSize;
    }

    @Override
    public int getCoreSize() {
        if (isShutdown) {
            throw new IllegalStateException("The thread pool is destroy");
        }
        return this.coreSize;
    }

    @Override
    public int getQueueSize() {
        if (isShutdown) {
            throw new IllegalStateException("The thread pool is destroy");
        }
        return runnableQueue.size();
    }

    @Override
    public int getActiveCount() {
        synchronized (this) {
            return this.activeCount;
        }
    }

    @Override
    public boolean isShutdown() {
        return this.isShutdown;
    }


    private static class ThreadTask {
        public ThreadTask(Thread thread, InternalTask internalTask) {
            this.thread = thread;
            this.internalTask = internalTask;
        }

        Thread thread;

        InternalTask internalTask;
    }
}