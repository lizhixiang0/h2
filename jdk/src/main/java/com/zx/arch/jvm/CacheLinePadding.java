package com.zx.arch.jvm;

/**
 * @author lizx
 * @date 2021/9/26
 * @since
 * @description  测试缓存行
 **/
public class CacheLinePadding {
    private static class Padding {
        //一个long是8个字节，一共7个long
        public volatile long p1, p2, p3, p4, p5, p6;
    }

    private static class T extends Padding {
        //x变量8个字节，加上Padding中的变量，刚好64个字节，独占一个缓存行。
        public volatile long x = 0L;   // 1、加了volatile，保证修改时会遵从缓存一致性协议！写入内存时将其他线程的缓存块设置为无效
    }

    public static T[] arr = new T[2];   // 2、将两个变量存到一个连续的数组中去，这样如果arr不满64字节，那大概率会把他们放到同一个缓存块！

    static {
        arr[0] = new T();
        arr[1] = new T();
    }

    public static void main(String[] args) throws Exception {
        Thread t1 = new Thread(() -> {
            for (long i = 0; i < 10000000; i++) {
                arr[0].x = i;   // 3、不断修改
            }
        });

        Thread t2 = new Thread(() -> {
            for (long i = 0; i < 10000000; i++) {
                arr[1].x = i;  // 4、不断修改
            }
        });

        final long start = System.nanoTime();
        t1.start();
        t2.start();
        t1.join();
        t2.join();
        System.out.println((System.nanoTime() - start)  / 100000);
    }
}
