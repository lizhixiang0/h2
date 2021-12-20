package com.wangwenjun.concurrent.chapter01;

import java.util.concurrent.TimeUnit;

/**
 * 注:多核下通过这种1s停顿的方式并不会交替执行
 * @author admin
 */
public class TryConcurrency {
    public static void main(String[] args) {
        new Thread(TryConcurrency::enjoyMusic).start();
        browseNews();
    }

    /**
     * Browse the latest news.
     */
    private static void browseNews() {
        for (; ; ) {
            System.out.println("Uh-huh, the good news.");
            sleep(1);
        }
    }

    /**
     * Listening and enjoy the music.
     */
    private static void enjoyMusic() {
        for (; ; ) {
            System.out.println("Uh-huh, the nice music.");
            sleep(1);
        }
    }

    /**
     * Simulate the wait and ignore exception.
     *
     * @param seconds
     */
    private static void sleep(int seconds) {
        try {
            TimeUnit.SECONDS.sleep(seconds);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
