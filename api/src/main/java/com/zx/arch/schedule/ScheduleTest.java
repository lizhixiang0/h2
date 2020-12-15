package com.zx.arch.schedule;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

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

    @Scheduled(cron = "0 */1 * * * ?")
    public void searchPendingTaskAndCommit() {
        // ddd
    }
}
