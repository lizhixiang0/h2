package com.wangwenjun.concurrent.chapter05.custom_lock;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.IntStream;

import static java.lang.Thread.currentThread;
import static java.util.concurrent.ThreadLocalRandom.current;

/**
 * 测试自定义的 BooleanLock
 * @author admin
 */
public class BooleanLockTest
{

    private final Lock lock = new BooleanLock();

    public void syncMethod() {
        try {
            lock.lock();
            System.out.println(currentThread() + " get the lock.");
            int randomInt = current().nextInt(10);
            TimeUnit.SECONDS.sleep(randomInt);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            lock.unlock();
        }
    }

    public void syncMethodTimeoutable()
    {
        try
        {
            // 一秒钟之内需要获得锁
            lock.lock(1000);
            System.out.println(currentThread() + " get the lock.");
            int randomInt = current().nextInt(10);
            TimeUnit.SECONDS.sleep(randomInt);
        } catch (InterruptedException | TimeoutException e)
        {
            e.printStackTrace();
        } finally
        {
            lock.unlock();
        }
    }

    /**
     * 测试BooleanLock 控制加锁和释放锁
     */
    public static void test_BooleanLock(){
        BooleanLockTest blt = new BooleanLockTest();
        IntStream.range(0, 10)
                .mapToObj(i -> new Thread(blt::syncMethod))
                .forEach(Thread::start);
    }

    /**
     * 测试BooleanLock控制获取锁资源的时间, 俗称Fail-fast
     */
    public static void test_BooleanLock_fast_fail() throws InterruptedException {
        BooleanLockTest blt = new BooleanLockTest();
        new Thread(blt::syncMethod, "T1").start();
        TimeUnit.MILLISECONDS.sleep(2);

        Thread t2 = new Thread(blt::syncMethodTimeoutable, "T2");
        t2.start();
        TimeUnit.MILLISECONDS.sleep(10);
    }

    /**
     * 测试BooleanLock响应中断
     */
    public static void test_BooleanLock_interrupt() throws InterruptedException {
        BooleanLockTest blt = new BooleanLockTest();

        new Thread(blt::syncMethod, "T1").start();

        Thread t2 = new Thread(blt::syncMethodTimeoutable, "T2");
        t2.start();
        TimeUnit.MILLISECONDS.sleep(10);
        t2.interrupt();
    }


    public static void main(String[] args) throws InterruptedException {
        test_BooleanLock_fast_fail();
    }
}
