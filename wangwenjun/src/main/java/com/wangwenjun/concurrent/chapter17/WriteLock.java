package com.wangwenjun.concurrent.chapter17;

/**
 * 写锁
 */
class WriteLock implements Lock {

    private final ReadWriteLockImpl readWriteLock;

    WriteLock(ReadWriteLockImpl readWriteLock) {
        this.readWriteLock = readWriteLock;
    }

    @Override
    public void lock() throws InterruptedException {
        synchronized (readWriteLock.getMutex()) {
            try {
                readWriteLock.incrementWaitingWriters();
                // 当前存在正在读的线程或者存在正在写的线程,则wait
                while (readWriteLock.getReadingReaders() > 0 || readWriteLock.getWritingWriters() > 0) {
                    readWriteLock.getMutex().wait();
                }
            } finally {
                this.readWriteLock.decrementWaitingWriters();
            }
            readWriteLock.incrementWritingWriters();
        }
    }

    @Override
    public void unlock() {
        synchronized (readWriteLock.getMutex()) {
            readWriteLock.decrementWritingWriters();
            // 我个人建议这个不要设置为false
            readWriteLock.changePrefer(false);
            readWriteLock.getMutex().notifyAll();
        }
    }
}
