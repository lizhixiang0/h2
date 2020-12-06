package com.zx.arch.threads;

import lombok.SneakyThrows;

/**
 * @author lizx
 * @date 2020/08/07
 * @description 开启线程的方式之一、继承Thread,将任务写道run方法中,然后调用start启动线程
 * @thread 利用线程做异步操作,但是这样不靠谱,比较完美的做法是利用线程池
 **/
public class OneThread extends Thread{
    @SneakyThrows
    @Override
    public void run() {
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("高!");
    }

    public static void main(String[] args) {
        System.out.println(new OneThread().s("我高吗？"));
    }

    public String s (String s){
        new OneThread().start();
        return s;
    }
}
