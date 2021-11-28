package com.wangwenjun.concurrent.chapter07;

import java.util.concurrent.TimeUnit;

/**
 * 如果没有为子线程设置UncaughtExceptionHandler,使用线程组的uncaughtException方法 （线程组实现了UncaughtExceptionHandler接口）
 *
 * 如果线程组有父线程组,那就调用父线程组的uncaughtException方法
 * 父线程组继续找爷爷线程组，直到找不到为止,然后查看是或否设置了线程全局UncaughtExceptionHandler！
 * 没设置全局UncaughtExceptionHandler，那就将错误信息压到System.err中
 *
 * 说到底就是一直往上翻，看看有没有那个祖宗线程组重写了UncaughtExceptionHandler方法的，是在没有就看看有没有默认处理器，最后没法办法就调用system.err.print
 * @author admin
 */
public class EmptyExceptionHandler {
    public static void main(String[] args)
    {
        ThreadGroup mainGroup = Thread.currentThread().getThreadGroup();
        System.out.println(mainGroup.getParent());
        // 可以看到线程组没有父线程组，另外我也没设置全局UncaughtExceptionHandler
        System.out.println(mainGroup.getParent().getParent());

        final Thread thread = new Thread(() -> {
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException e) {
            }
            //here will throw unchecked exception.
            System.out.println(1 / 0);
        }, "Test-Thread");

        thread.start();
    }
}
