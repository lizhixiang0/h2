package com.zx.arch.threads;

import java.util.concurrent.*;

/**
 * @author lizx
 * @date 2020/08/07
 * @description 开启多线程之四、线程池  这也是最推荐的方式
 *              开启方式: 四种线程池、根据需要选择/但是,一般还是推荐手动创建线程池
 *              优点
     *              1、线程池内线程可以重复利用、节约系统资源
     *              2、可以防止开启大量线程、导致系统崩盘
     *              3、提高响应速度,不需要等待线程创建就能立即执行
 * @blog  "https://www.cnblogs.com/jiawen010/p/11855768.html
 * @info  线程池中对异常的处理和平时不一样,要着重关注！！！ "https://blog.csdn.net/weixin_37968613/article/details/108407774
 * @note springboot项目中使用线程池:"https://www.jianshu.com/p/d1847ecd6b29
 *                                https://blog.csdn.net/weixin_38399962/article/details/82146480
 **/
public class ThreadPool {


    public static void main(String[] args) {
        /**
         * 固定可重用线程(内部使用的无界队列)   注：实际生产中不可能使用固定可重用线程,(就是因为无界队列)，会有内存隐患。
         * 详情看:https://segmentfault.com/a/1190000013292447
         */
        ExecutorService fixedThreadPool = Executors.newFixedThreadPool(3);

        for(int i = 0; i < 12; i++) {
            fixedThreadPool.execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        System.out.println(Thread.currentThread().getName());
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            });
        }
    }
    /*一共12个任务，每次开启三个线程，一个任务睡2s,总共需要8秒*/
}
