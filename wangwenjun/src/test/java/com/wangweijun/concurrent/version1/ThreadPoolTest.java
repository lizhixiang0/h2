package com.wangweijun.concurrent.version1;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * @author lizx
 * @date 2021/12/10
 * @since
 **/
public class ThreadPoolTest {
    public static void main(String[] args) {
        ThreadPoolImpl threadPool = ThreadPoolImpl.newInstance();
        threadPool.exec();
        for (int i=0;i<100;i++){
            int finalI = i;
            threadPool.putTask(() -> System.out.println(Thread.currentThread().getName()+"           我是一個任務"+ finalI));
        }
    }
}
