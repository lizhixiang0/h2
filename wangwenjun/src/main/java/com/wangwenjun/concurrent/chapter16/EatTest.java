package com.wangwenjun.concurrent.chapter16;

import netscape.security.UserTarget;

import java.util.concurrent.TimeUnit;

/***************************************
 * @author:Alex Wang
 * @Date:2017/11/27
 * QQ: 532500648
 * QQ群:463962286
 ***************************************/
public class EatTest {
    public static void main(String[] args) throws InterruptedException {
        // 一副刀叉
        Tableware fork = new Tableware("fork");
        Tableware knife = new Tableware("knife");
        TablewarePair tablewarePair = new TablewarePair(fork, knife);
        // A, B 两个人吃面
        Long start = System.currentTimeMillis();
        EatNoodleThread a = new EatNoodleThread("A", tablewarePair);
        EatNoodleThread b = new EatNoodleThread("B", tablewarePair);

        a.start();
        b.start();

        a.join();
        b.join();
        Long time = System.currentTimeMillis() - start;



        System.out.println(time);
    }
}
