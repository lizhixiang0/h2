package com.wangwenjun.concurrent.chapter13;

import com.wangwenjun.concurrent.chapter23.CountDownLatch;
import com.wangwenjun.concurrent.chapter23.Latch;

import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * 测试volatile无法保证原子性
 *
 * @author admin
 */
public class VolatileTest {
    private static volatile int count = 0;
    /**
     * 用来让主线程等待子线程全部执行完,之前我用的join,太麻烦了
     */
    private static final Latch latch = new CountDownLatch(10);

    /**
     * count++ 不是个原子操作，分为三步
     * <p>
     * 第一步：从主内存读取iz值,并存储到工作内存,如果工作内存中存在则直接使用  （执行完后 切换线程或者其他线程写入主内存导致当前工作内存的i值失效没关系，重新读取就是了）
     * 第二步：进行+1操作  （执行完 切换线程或者其他线程写入主内存导致当前工作内存的i值失效，则重新从主内存读取i值，当前+1操作等于白加了）
     * 第三步：写入主内存   （执行完，线程结束，不影响）
     */
    private static void inc() {
        count++;
    }

    public static void main(String[] args) throws InterruptedException {
        IntStream.range(0, 10).forEach(
                item -> new Thread(() -> {
                    for (int x = 0; x < 1000; x++) {
                        inc();
                    }
                    latch.countDown();
                }).start()
        );
        latch.await();
        System.out.println(count);
    }
}