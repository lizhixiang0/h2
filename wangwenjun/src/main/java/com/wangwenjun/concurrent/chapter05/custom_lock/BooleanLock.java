package com.wangwenjun.concurrent.chapter05.custom_lock;


import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import static java.lang.System.currentTimeMillis;
import static java.lang.Thread.currentThread;

/**
 * 自定义显示锁
 * 这里补充下,所有的加锁方式本质上都是同步阻塞！并不会因为使用不同的加锁方式导致效率产生变化！
 * 区别只在于控制加锁的流程！比如这里定义BooleanLock,可以控制加锁和释放锁的时机！
 * 以及可以控制请求不到锁则抛出异常！原先直接使用synchronized，加不到锁就陷入阻塞！现在相当于做了一层包装，加了一层时间控制！控制阻塞时间！
 *
 * @author admin
 */
public class BooleanLock implements Lock {

    private Thread currentThread;
    /**
     * 加锁时,线程跑过来看locked,为true则wait,为false则加锁成功！同时加锁成功后将locked改成true ,阻塞其他线程！
     * 释放锁时,将locked设置为false, 同时唤醒所有线程
     *
     * 注意：所有更改共享变量的行为都需要加锁！所以这两个方法是要加同步锁的！
     */
    private boolean locked = false;

    /**
     * 不一定需要这个容器,主要是定义了getBlockedThreads方法
     */
    private final List<Thread> blockedList = new ArrayList<>();

    @Override
    public void lock() throws InterruptedException {
        // 无论多少个线程方法,只有一个线程能进入同步块，那这里用list存储blockedList的线程意义是啥？我忘了了，wait方法会释放锁资源，此时其他线程也会进入while循环
        synchronized (this) {
            while (locked) {
                if (!blockedList.contains(Thread.currentThread())) {
                    blockedList.add(currentThread());
                }
                // 假如两个线程堆积在这里,此时第三个线程执行notifyAll，那么这两个线程会不会同时读到locked = false ?
                // 网上资料说,notifyAll会唤醒所有线程，但是此时只会有一个线程获得锁!其他线程还是保持在wait状态！那这样和notify()有啥区别？
                this.wait();
            }
            blockedList.remove(currentThread());
            this.locked = true;
            this.currentThread = currentThread();
        }
    }

    @Override
    public void lock(long mills) throws InterruptedException, TimeoutException {
        synchronized (this) {
            // 参数有问题不抛出异常,直接调用lock()
            if (mills <= 0) {
                this.lock();
            } else {
                // 剩余时间 = 终点时刻-当前时刻  (一开始等于控制时间)
                long remainingMills = mills;
                // 终点时刻 = 当前时间 + 控制时间  (终点时刻不会变化)
                long endMills = currentTimeMillis() + mills;

                while (locked) {
                    // 剩余时间没有了则抛出异常，否则继续执行
                    if (remainingMills <= 0) {
                        throw new TimeoutException("can not get the lock during " + mills + " ms.");
                    }

                    if (!blockedList.contains(currentThread())) {
                        blockedList.add(currentThread());
                    }
                    // 控制线程wait ，传入wait时间(剩余时间) , 此时有4种情况
                    /*
                    * 1、直接睡到醒，那没毛病,醒来继续循环，然后抛出异常
                    * 2、睡到一半，被notifyAll唤醒，也没毛病，醒来获得锁
                    * 3、睡到一半，被notifyAll唤醒，拿不到锁，继续wait
                    * 4、睡到一半，响应中断，所以用try包住wait,响应中断后需要将blockedList中的本线程剔除掉,避免内存泄漏
                    * */
                    try{
                        this.wait(remainingMills);
                    }catch (InterruptedException e){
                        blockedList.remove(currentThread());
                        throw e;
                    }


                    remainingMills = endMills - currentTimeMillis();
                }

                blockedList.remove(currentThread());
                this.locked = true;
                this.currentThread = currentThread();
            }
        }
    }

    @Override
    public void unlock() {
        // unlock是个同步方法
        synchronized (this) {
            if (currentThread == currentThread()) {
                this.locked = false;
                Optional.of(currentThread().getName() + " release the lock monitor.").ifPresent(System.out::println);
                this.notifyAll();
            }
        }
    }

    @Override
    public List<Thread> getBlockedThreads()
    {
        return Collections.unmodifiableList(blockedList);
    }
}