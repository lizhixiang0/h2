package com.wangwenjun.concurrent.chapter04;

import java.util.Collections;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

/**
 * 体会下高并发下HashMap出现线程假死
 * @author admin
 */
public class HashMapDeadLock {

    private final HashMap<String, String> map = new HashMap<>();

    public void add(String key, String value) {
        this.map.put(key, value);
    }

    /**
     * 开两个线程,不断往HashMap中put数据
     */
    public void test_hashMap_dead_lock(){
        final HashMapDeadLock hmdl = new HashMapDeadLock();
        for (int x = 0; x < 2; x++) {
            new Thread(() -> {
                for (int i = 1; i < Integer.MAX_VALUE / 8; i++) {
                    hmdl.add(String.valueOf(i), String.valueOf(i));
                }
            }).start();
        }
    }


    public static void main(String[] args) {
        // HashMap 高并发下会出现线程假死(即死循环引起的死锁),此时没有线程处于blocked状态，cpu使用率会很高,甚至工具都执行不了
        // 此时使用jstack、jconsole、jvisualvm是看不出啥的,可以使用jProfiler(收费的)看下方法执行时间,如果一个方法执行很久有可能是陷入了死循环
        // 最好是远程启动jProfiler,因为本机cpu资源可能被耗尽
        new HashMapDeadLock().test_hashMap_dead_lock();
    }
}
