package com.zx.arch.concurrency.connectionPool;


import java.sql.Connection;
import java.util.LinkedList;

/**
 * 线程池的要求：
 *              1、释放一个连接意味着可以拿一个连接  （生产者消费者）
 *              2、获取连接需要同步，拿不到线程就wait，等待释放线程后再尝试获得
 *
 * synchronized的生产者和消费者模型 （加了一个限时,如果不加限时,线程会一直处于等待的状态，有两个问题，一是用户不耐烦，而是线程数会越来越多）
 *
 *
 * @author admin
 * @description
 */
public class ConnectionPool {

    private LinkedList<Connection> pool = new LinkedList<>();

    public ConnectionPool(int initialSize) {
        if (initialSize > 0) {
            for (int i = 0; i < initialSize; i++) {
                pool.addLast(ConnectionDriver.createConnection());
            }
        }
    }

    /**
     * 生产者：释放数据库连接
     * @param connection
     */
    public void releaseConnection(Connection connection) {
        if (connection != null) {
            synchronized (pool) {
                pool.addLast(connection);
                pool.notifyAll();
            }
        }
    }

    /**
     * 消费者：获取数据库连接
     * @param mills
     * @return
     * @throws InterruptedException
     */
    public Connection fetchConnection(long mills) throws InterruptedException {
        synchronized (pool) {
            // mills小于0说明不用限时
            if (mills <= 0) {
                while (pool.isEmpty()) {
                    pool.wait();
                }
                return pool.removeFirst();
            } else {
                // 限时,mills时间内拿不到返回null
                long future = System.currentTimeMillis() + mills;
                long remaining = mills;
                while (pool.isEmpty() && remaining > 0) {
                    pool.wait(remaining);
                    remaining = future - System.currentTimeMillis();
                }

                Connection result = null;
                if (!pool.isEmpty()) {
                    result = pool.removeFirst();
                }
                return result;
            }
        }
    }
}
