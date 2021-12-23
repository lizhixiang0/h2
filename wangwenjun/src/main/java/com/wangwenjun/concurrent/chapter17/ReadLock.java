package com.wangwenjun.concurrent.chapter17;

/**
 * 读锁实现
 */
class ReadLock implements Lock {

    private final ReadWriteLockImpl readWriteLock;

    ReadLock(ReadWriteLockImpl readWriteLock) {
        this.readWriteLock = readWriteLock;
    }

    @Override
    public void lock() throws InterruptedException {
        synchronized (readWriteLock.getMutex()) {
            //  若当前有线程正在写 或者 有其他线程请求写操作并且写操作优先,则本线程 wait
            //  否则ReadingReaders+1,然后释放锁   (如果当前存在线程在进行读操作，则不影响，不会wait,读读不互斥就是这么来的)
            while (readWriteLock.getWritingWriters() > 0 || (readWriteLock.getPreferWriter() && readWriteLock.getWaitingWriters() > 0)) {
                readWriteLock.getMutex().wait();
            }
            readWriteLock.incrementReadingReaders();
        }
    }

    @Override
    public void unlock() {
        synchronized (readWriteLock.getMutex()) {
            // ReadingReaders-1
            readWriteLock.decrementReadingReaders();
            // 修改为写操作优先
            readWriteLock.changePrefer(true);
            // 唤醒所有wait的写线程
            readWriteLock.getMutex().notifyAll();
        }
    }
}
