package com.wangwenjun.concurrent.chapter01;

import java.util.concurrent.TimeUnit;

/***************************************
 * @author:Alex Wang
 * @Date:2017/10/22
 * 532500648
 ***************************************/
public class DuplicatedStartThread
{
    public static void main(String[] args) throws InterruptedException
    {
        Thread thread = new Thread(() -> {
            try
            {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        });
        thread.start();
        TimeUnit.SECONDS.sleep(2);
        // 对一个Thread调用两次start会发生什么?
        // 创建线程到底有几种方式？
        thread.start();
    }
}
