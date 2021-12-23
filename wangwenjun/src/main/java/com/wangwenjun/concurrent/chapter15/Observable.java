package com.wangwenjun.concurrent.chapter15;

/**
 * @author admin
 */
public interface Observable {
    enum Cycle {
        STARTED, RUNNING, DONE, ERROR
    }

    Cycle getCycle();

    void start();
}
