package com.wangwenjun.concurrent.chapter15;

import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

/**
 * @author admin
 * @description 有返回值的任务
 */
public interface Task<T> extends Callable {
    @Override
    T call();


    class Default implements Task{
        @Override
        public Object call() {
            try {
                TimeUnit.SECONDS.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println(" finished done.");
            return "Hello Observer";
        }
    }
}
