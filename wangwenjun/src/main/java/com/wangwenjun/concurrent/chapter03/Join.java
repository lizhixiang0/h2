package com.wangwenjun.concurrent.chapter03;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static java.util.stream.Collectors.toList;

/**
 * 测试Join方法，Join方法比yield方法要靠谱
 * @author admin
 */
public class Join {

    /**
     * 线程sleep一分钟
     */
    private static void shortSleep() {
        try {
            TimeUnit.NANOSECONDS.sleep(1);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * 创建一个线程
     *
     * @param seq
     * @return
     */
    private static Thread create(int seq) {
        return new Thread(() -> {
            for (int i = 0; i < 5; i++) {
                System.out.println(Thread.currentThread().getName() + "#" + i);
                shortSleep();
            }
        }, String.valueOf(seq));
    }

    public static void main(String[] args) throws InterruptedException {
        // 1、创建两个线程,并启动
        List<Thread> threads = IntStream.range(1, 3).mapToObj(Join::create).collect(toList());
        threads.forEach(Thread::start);
        // 2、main线程调用两个线程的join方法
        for (Thread thread : threads) {
            thread.join();
        }

        System.out.println("===============");

        // 3、main线程会等待两个被join的线程执行完
        for (int i = 0; i < 5; i++) {
            System.out.println(Thread.currentThread().getName() + "#" + i);
            shortSleep();
        }
    }

}