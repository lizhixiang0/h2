package com.wangwenjun.concurrent.chapter17;

import static java.lang.Thread.currentThread;

/**
 *
 * @author admin
 */
public class ReadWriteLockTest {
    //This is the example for ReadWriteLock
    private final static String text = "a";

    public static void main(String[] args) {

        final ShareData shareData = new ShareData(50);
        // 2个线程进行写操作
        for (int i = 0; i < 2; i++) {
            new Thread(() -> {
                for (int index = 0; index < text.length(); index++) {
                    try {
                        char c = text.charAt(index);
                        shareData.write(c);
                        System.out.println(currentThread() + " write " + c);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
        // 10个线程进行读操作
        for (int i = 0; i < 10; i++) {
            new Thread(() -> {
                    try {
                        System.out.println(currentThread() + " read " + new String(shareData.read()));
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
            }).start();
        }
    }
}
