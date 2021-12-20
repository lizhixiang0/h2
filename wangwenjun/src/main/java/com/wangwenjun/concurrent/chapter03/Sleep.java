package com.wangwenjun.concurrent.chapter03;

/**
 * @author admin
 */
public class Sleep {

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
        }
    }

    public static void main(String[] args) {
        new Thread(() -> {
            long startTime = System.currentTimeMillis();
            sleep(2_000L); // 沉睡当前线程，不会放弃cpu资源
            long endTime = System.currentTimeMillis();
            System.out.println(String.format("Total spend %d ms", (endTime - startTime)));
        }).start();

        long startTime = System.currentTimeMillis();
        sleep(3_000L);
        long endTime = System.currentTimeMillis();

        System.out.println(String.format("Main thread total spend %d ms", (endTime - startTime)));

    }

}
