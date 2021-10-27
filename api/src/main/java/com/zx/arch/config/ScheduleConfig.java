package com.zx.arch.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * @author admin
 */
@Configuration
@EnableAsync
public class ScheduleConfig implements SchedulingConfigurer {

    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        // 可以使用spring的ThreadPoolTaskScheduler来构造线程池
        taskRegistrar.setScheduler(taskExecutor());
        // 也可以使用jdk的newScheduledThreadPool线程池
        taskRegistrar.setScheduler(Executors.newScheduledThreadPool(15));
    }


    /**
     * @return executor for the scheduler (naming convention)
     */
    @Bean(name = "taskScheduler")
    public Executor taskExecutor() {
        ThreadPoolTaskScheduler scheduledExecutorService = new ThreadPoolTaskScheduler();
        scheduledExecutorService.setPoolSize(4);
        scheduledExecutorService.setThreadNamePrefix("appscan-coordinator-scheduler-");
        scheduledExecutorService.setWaitForTasksToCompleteOnShutdown(false);

        return scheduledExecutorService;
    }

}
