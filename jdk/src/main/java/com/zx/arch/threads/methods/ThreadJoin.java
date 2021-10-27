package com.zx.arch.threads.methods;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * @author lizx
 * @date 2021/10/25
 * @since
 **/
public class ThreadJoin {
    public static void main(String[] args) throws InterruptedException {
        List<Thread> threads = IntStream.range(1,3).mapToObj(ThreadJoin::create).collect(Collectors.toList());
        threads.forEach(Thread::start);

        // 主线程阻塞,等待2个子线程执行完，虽然调用一次join就能确保主线程阻塞，但是还需要确保所有子线程都执行完，所以需要写个循环，在主线程里调用每个子线程的join方法
        for (Thread thread:threads){
            thread.join();
        }

        for (int i = 0; i < 10 ; i++) {
            System.out.println("线程"+ Thread.currentThread().getName()+ "#" + i);
            shortSleep();
        }
    }

    private static Thread create(int seq){
        return new Thread(()->{
            for(int i = 0;i<10;i++){
                System.out.println("线程"+Thread.currentThread().getName()+ "#" + i);
                // sleep会释放cpu,所以造成两个线程轮流执行的现象
                shortSleep();
            }
        }, String.valueOf(seq));
    }
    private static void shortSleep() {
        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

    }
}
