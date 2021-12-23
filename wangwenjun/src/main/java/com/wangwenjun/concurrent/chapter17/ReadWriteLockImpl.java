package com.wangwenjun.concurrent.chapter17;

/***************************************
 * @author:Alex Wang
 * @Date:2017/11/25
 * QQ: 532500648
 * QQ群:463962286
 ***************************************/
class ReadWriteLockImpl implements ReadWriteLock {

    /**
     * 锁,读锁和写锁要保证互斥,必须使用同一把锁！
     */
    private final Object MUTEX = new Object();

    /**
     * 用来控制倾向,一般读写锁使用在读多写少的环境,所以这个参数用来保证一旦有线程尝试写操作,那就迅速执行这个操作！否则写操作线程不知道要等到什么时候！
     */
    private boolean preferWriter;
    /**
     * 记录正在写的线程数
     */
    private int writingWriters = 0;
    /**
     * 记录正在等待写锁的线程数
     */
    private int waitingWriters = 0;
    /**
     * 记录正在读的线程数
     */
    private int readingReaders = 0;

    /**
     * 默认写操作优先
     */
    public ReadWriteLockImpl()
    {
        this(true);
    }

    public ReadWriteLockImpl(boolean preferWriter)
    {
        this.preferWriter = preferWriter;
    }

    void incrementWritingWriters() {
        this.writingWriters++;
    }

    void incrementWaitingWriters()
    {
        this.waitingWriters++;
    }

    void incrementReadingReaders()
    {
        this.readingReaders++;
    }

    void decrementWritingWriters()
    {
        this.writingWriters--;
    }

    void decrementWaitingWriters()
    {
        this.waitingWriters--;
    }

    void decrementReadingReaders()
    {
        this.readingReaders--;
    }

    Object getMutex()
    {
        return this.MUTEX;
    }

    boolean getPreferWriter()
    {
        return this.preferWriter;
    }

    void changePrefer(boolean preferWriter)
    {
        this.preferWriter = preferWriter;
    }

    @Override
    public Lock readLock() { return new ReadLock(this); }

    @Override
    public Lock writeLock() {
        return new WriteLock(this);
    }

    @Override
    public int getWritingWriters() {
        return this.writingWriters;
    }

    @Override
    public int getWaitingWriters() {
        return this.waitingWriters;
    }

    @Override
    public int getReadingReaders() {
        return this.readingReaders;
    }


}