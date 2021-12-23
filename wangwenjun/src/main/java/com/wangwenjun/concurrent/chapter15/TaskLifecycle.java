package com.wangwenjun.concurrent.chapter15;

/**
 * @author admin
 * @description 任务生命的不同期间执行不同的方法
 */
public interface TaskLifecycle<T> {

    void onStart(Thread thread);

    void onRunning(Thread thread);

    void onFinish(Thread thread, T result);

    void onError(Thread thread, Exception e);

    class EmptyLifecycle<T> implements TaskLifecycle<T> {

        @Override
        public void onStart(Thread thread) {
            //do nothing
        }

        @Override
        public void onRunning(Thread thread) {
            //do nothing
        }

        @Override
        public void onFinish(Thread thread, T result) {
            System.out.println("The result is " + result);
        }

        @Override
        public void onError(Thread thread, Exception e) {
            //do nothing
        }
    }
}
