package com.zx.arch.threads;

import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

/**
 * @author lizx
 * @date 2020/08/07
 * @description 开启多线程之三、实现Callable接口、改写call方法 、用FutureTask包装交给Thread
 *              相比Runnable的优势：
 *                  1、call方法可以返回值，run方法不能
 **/
public class OneCallable implements Callable {

    @Override
    public Object call() throws Exception {
        Thread.sleep(5000);
        System.out.println("帅!");
        return null;
    }

    public static void main(String[] args) {
        System.out.println(new OneCallable().s("我帅吗？"));;
    }

    public String s (String s){
        new Thread(new FutureTask(new OneCallable())).start();
        return s;
    }
}
