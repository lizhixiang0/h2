package com.zx.arch.threads.studyOne;


/**
 * @author lizx
 * @date 2020/12/20
 * @description java线程内存模型之线程的工作空间
 *
 **/
public class Demo04 {
    //不加volatile,线程1感知不到线程2改变了ready ! 原因就在于每个线程都有自己的工作空间！操纵的是主内存里的共享变量副本
    private static  volatile  boolean ready;

    public static void main(String[] args) throws InterruptedException {
        System.out.println("waiting data");
        new Thread(() -> {
            while (!ready) {
            }
            System.out.println("================go to use data");
        }).start();

        Thread.sleep(2000);

        new Thread(()->{
            prepare();
        }).start();
    }

    public static void prepare(){
        System.out.println("ready to prepare date");
        ready = true;
        System.out.println("prepare date success");
    }
}
