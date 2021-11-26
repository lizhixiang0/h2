package com.wangwenjun.concurrent.chapter05;

/**
 * 线程调用某个对象的wait方法时,会加入该对象对应的wait set中,而这个wait set 存储在对象头的monitor中 ！所以調用wait方法要求持有monitor鎖
 *
 * 调用某个对象notify方法时,会从该对象的wait set中弹出一个线程 （notifyAll 是弹出所有线程） ！同样也需要持有monitor锁！
 * 并且 wait方法是能够响应中断的，如果该线程被的wait状态被中断，则会从wait set中弹出，同时清除中断标志
 *
 * 总结：使用那个对象的wait & notify ,必须持有该对象的monitor锁！换句话说,必须在同步块中调用
 *
 * 补充：
 *      notify()方法： 当使用某个对象的notify()方法时，将从该对象的等待集合中选择一个等待的线程唤醒，唤醒的线程将从等待集合中删除。
 *
 *      notifyAll()方法：notifyAll()方法会将所有在等待集合中的线程唤醒，但由于所有的被唤醒的线程仍然要去争用synchronized锁，而synchronized锁具有排他性，最终只有一个线程获得该锁，进行执行状态，其他线程仍要继续等待。
 * @author admin
 */
public class WaitNotify {

    private final Object MUTEX = new Object();

    private synchronized void testWait() {
        try
        {
            MUTEX.wait();
        } catch (InterruptedException e)
        {
            e.printStackTrace();
        }
    }

    private synchronized void testNotify()
    {
        MUTEX.notifyAll();
    }

    public static void main(String[] args) {
        WaitNotify waitNotify = new WaitNotify();
        waitNotify.testNotify();
    }
}
