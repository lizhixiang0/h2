package com.wangwenjun.concurrent.chapter17;

/**
 * 定义读写锁,这个类的主要目的是创建读锁和写锁，并且可以统计读线程数、写线程数 (实现读写锁分别用到这些数据)
 *
 * 可以思考下为什么要在readLock和writeLock的基础上创建一个ReadWriteLock ？思考下！
 *
 * @author admin
 */
public interface ReadWriteLock {
    // 创建读锁
    Lock readLock();
    // 创建写锁
    Lock writeLock();

    // 获取当前正在执行写操作的线程数
    int getWritingWriters();

    // 获取当前正在等待写锁的线程数
    int getWaitingWriters();

    //  获取当前正在执行读操作的线程数
    int getReadingReaders();


    // 工厂方法: 创建ReadWriteLock
    static ReadWriteLock readWriteLock()
    {
        return new ReadWriteLockImpl();
    }
    // 工厂方法: 创建ReadWriteLock
    static ReadWriteLock readWriteLock(boolean preferWriter)
    {
        return new ReadWriteLockImpl(preferWriter);
    }
}
