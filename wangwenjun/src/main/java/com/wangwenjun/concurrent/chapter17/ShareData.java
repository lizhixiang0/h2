package com.wangwenjun.concurrent.chapter17;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 代表共享资源
 * @author admin
 */
public class ShareData {

    private final List<Character> container = new ArrayList<>();

    private final ReadWriteLock readWriteLock = ReadWriteLock.readWriteLock();

    private final Lock readLock = readWriteLock.readLock();

    private final Lock writeLock = readWriteLock.writeLock();

    private final int length;

    public ShareData(int length) {
        this.length = length;
        for (int i = 0; i < length; i++) {
            container.add(i, 'c');
        }
    }

    public char[] read() throws InterruptedException {
        try {
            readLock.lock();
            char[] newBuffer = new char[length];
            for (int i = 0; i < length; i++) {
                newBuffer[i] = container.get(i);
            }
            network_call();
            return newBuffer;
        } finally {
            readLock.unlock();
        }
    }

    public void write(char c) throws InterruptedException {
        try {
            writeLock.lock();
            for (int i = 0; i < length; i++) {
                this.container.add(i, c);
            }
            network_call();
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * 用来模拟控制读写的时长，通常情况对共享变量的读写不会占很多时间，但是如果是进行网络查询，然后进行操作，就不一定
     *
     * 这里进行一下统计, 读操作和写操作都是需要一秒钟
     * 总共12个线程,如果是之前不管读写操作,则12个线程的操作都互斥，总共需要 12s
     * 这个我们使用读写锁分离,只需要 3秒
     *
     */
    private void network_call() {
        try {
            // 延迟1s
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}