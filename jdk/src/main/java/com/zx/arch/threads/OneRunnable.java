package com.zx.arch.threads;

import lombok.SneakyThrows;

/**
 * @author lizx
 * @date 2020/08/07
 * @description 开启线程方法之二、实现Runnable接口，这个比thread方式要好
 **/
public class OneRunnable implements Runnable {
    @SneakyThrows
    @Override
    public void run() {
        Thread.sleep(5000);
        System.out.println("富!");
    }

    public static void main(String[] args) {
        System.out.println(new OneRunnable().s("我富吗？"));;
    }

    public String s (String s){
        new Thread(new OneRunnable()).start();
        return s;
    }
}
