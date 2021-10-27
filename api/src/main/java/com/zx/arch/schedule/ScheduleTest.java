package com.zx.arch.schedule;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * @author lizx
 * @since 1.0.0
 * @description  定时任务没啥说的这里主要介绍ApplicationListener<ContextRefreshedEvent>的用法
 *                主要就是项目会在所有bean 完成初始化之后调用onApplicationEvent方法
 *                "https://blog.csdn.net/li_jiazhi/article/details/104117417
 */
@Component
@Configurable
@EnableScheduling
public class ScheduleTest implements ApplicationListener<ContextRefreshedEvent> {

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        /*自己的代码*/
        /*paxstore的例子：服务器重启清空缓存*/
       // for (String cacheName : CacheNames.AUTO_CLEAN_CACHE_NAMES) {
         //   cacheService.removeAll(cacheName);
        //}
    }

    /*
    *   单个线程运行：期望每个方法相隔1分钟运行,但是方法之间会互相干扰，导致test2隔了2分钟20s才运行
            scheduling-1  测试2  Wed Oct 20 13:53:00 CST 2021
            scheduling-1  测试1  Wed Oct 20 13:54:10 CST 2021
            scheduling-1  测试2  Wed Oct 20 13:55:20 CST 2021

         多线程运行：两个方法不会互相干扰！但是如果方法本身执行时间过长,比如周期是1分钟，但是执行时间为1分10秒，那么即使执行周期到了，也不会执行，只能等待下一个满一分钟，所以这里变成了2分钟执行一次
            scheduler-1   测试1  Wed Oct 20 14:04:00 CST 2021
            scheduler-2   测试2  Wed Oct 20 14:04:00 CST 2021
            scheduler-1   测试2  Wed Oct 20 14:06:00 CST 2021
            scheduler-2   测试1  Wed Oct 20 14:06:00 CST 2021
    *
    *
    *
    * */

//    @Scheduled(cron = "0 */1 * * * ?")
//    public void test1() throws InterruptedException {
//        System.out.println(Thread.currentThread().getName()+  "测试1"+  new Date());
//        Thread.sleep(1000*70); //沉睡70秒
//    }
//
//    @Scheduled(cron = "0 */1 * * * ?")
//    public void test2() throws InterruptedException {
//        System.out.println(Thread.currentThread().getName()+  "测试2"+  new Date());
//        Thread.sleep(1000*70);
//    }
}
