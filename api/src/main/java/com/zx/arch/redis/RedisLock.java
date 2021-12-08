package com.zx.arch.redis;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
@Documented
public @interface RedisLock {

    String prefix() default "";
    String key() default "";

    /**
     * 秒，锁的失效时间，如果job执行时间太长，另一个server可能会在第二次轮训的时候拿到任务
     * @return
     */
    int timeout() default 60;

    /**
     * 4096毫秒，保护时间，避免job执行太快，两个server同时拿到任务
     *
     *
     * 主要原因：这个redisLock一般是加在定时任务的方法上面,通常会有很多server一起跑
     * 定时任务无法保证两台server是同一时刻getLock,如果server1 执行很快(几毫秒),执行结果还未同步到数据库
     * 此时server2执行瞬间拿到锁，也去执行，此时server1的执行结果还未同步到数据库，就会出问题！
     *
     *
     * 解决方案就是，强制给每个 任务延长时间.
     *
     *
     * @return
     */
    long protectTime() default 2 << 11;

}