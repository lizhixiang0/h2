package com.zx.arch.concurrency.connectionPool;


import java.sql.Connection;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 6-18
 * @author admin
 */
public class ConnectionPoolTest {

    static ConnectionPool pool  = new ConnectionPool(10);

    static CountDownLatch start = new CountDownLatch(1);
    static CountDownLatch end;

    public static void main(String[] args) throws Exception {
        // 1、准备50个线程
        int threadCount = 2000;

        end = new CountDownLatch(threadCount);

        // 2、每个线程尝试获取连接20次
        int count = 20;

        AtomicInteger got = new AtomicInteger();

        AtomicInteger notGot = new AtomicInteger();

        for (int i = 0; i < threadCount; i++) {
            Thread thread = new Thread(new ConnetionRunner(count, got, notGot), "ConnectionRunnerThread");
            thread.start();
        }
        // 打开ConnetionRunner线程门闩
        start.countDown();

        // 主线程拉门栓，保证主线程在子线程全部执行完毕后再执行
        end.await();

        // 记录
        int total  = threadCount * count;
        System.out.println("total invoke: " + total);
        System.out.println("got connection:  " + got);
        System.out.println("not got connection " + notGot);

        System.out.println("rate: " + got.get() / notGot.get() );
    }

    static class ConnetionRunner implements Runnable {
        int           count;
        AtomicInteger got;
        AtomicInteger notGot;

        public ConnetionRunner(int count, AtomicInteger got, AtomicInteger notGot) {
            this.count = count;
            this.got = got;
            this.notGot = notGot;
        }

        @Override
        public void run() {
            try {
                // 1、线程一进来先等待，等待打开门闩  (保证线程同时执行)
                start.await();
            } catch (Exception ex) {
            }
            while (count > 0) {
                try {
                    Connection connection = pool.fetchConnection(1000);
                    if (connection != null) {
                        try {
                            connection.createStatement();
                            connection.commit();
                        } finally {
                            pool.releaseConnection(connection);
                            // 获取成功 +1
                            got.incrementAndGet();
                        }
                    } else {
                        // 获取失败 +1
                        notGot.incrementAndGet();
                    }
                } catch (Exception ex) {

                } finally {
                    count--;
                }
            }
            // 3、打开主线程门闩  （相同动作得执行50次）
            end.countDown();
        }
    }
}
