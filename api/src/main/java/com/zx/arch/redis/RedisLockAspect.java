package com.zx.arch.redis;

import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Aspect
@Component
public class RedisLockAspect {

    private static final Integer MAX_RETRY_COUNT = 3;
    private static final String LOCK_PRE_FIX = "prefix";
    private static final String LOCK_KEY = "key";
    private static final String TIME_OUT = "timeout";
    private static final String PROTECT_TIME = "protectTime";

    private static final Logger logger = LoggerFactory.getLogger(RedisLockAspect.class);

    @Pointcut("@annotation(com.zx.arch.redis.RedisLock)")
    public void redisLockAspect() {
    }

    @Around("redisLockAspect()")
    public void lockAroundAction(ProceedingJoinPoint proceeding) {

        //获取redis锁
        Map<String, Object> annotationArgs = this.getAnnotationArgs(proceeding);
        boolean flag = this.getLock(annotationArgs, 0, System.currentTimeMillis());
        if (flag) {
            //logger.debug(String.format("分布式任务锁获取成功:%s%s", annotationArgs.get(LOCK_PRE_FIX), annotationArgs.get(LOCK_KEY)));
            try {
                proceeding.proceed();
                Thread.sleep((long) annotationArgs.get(PROTECT_TIME));
            } catch (Throwable throwable) {
                logger.error("分布式任务执行异常: " + throwable.getMessage(), throwable);
            } finally {
                // 删除锁
                this.delLock(annotationArgs);
            }
        }
        /*else {
            logger.debug(String.format("分布式任务锁获取失败:%s%s", annotationArgs.get(LOCK_PRE_FIX), annotationArgs.get(LOCK_KEY)));
        }*/

    }

    /**
     * 获取锁
     */
    private boolean getLock(Map<String, Object> annotationArgs, int count, long currentTime) {
        //获取注解中的参数
        String lockPrefix = (String) annotationArgs.get(LOCK_PRE_FIX);
        String key = (String) annotationArgs.get(LOCK_KEY);
        int expire = (int) annotationArgs.get(TIME_OUT);
        long protectTime = (long) annotationArgs.get(PROTECT_TIME);
        if (StringUtils.isEmpty(lockPrefix) || StringUtils.isEmpty(key)) {
            // 此条执行不到
            logger.error("RedisLock,锁前缀,锁名未设置");
            return false;
        }
        if (RedisUtils.tryLock(lockPrefix + key, expire)) {
            return true;
        } else {
            // 如果当前时间与锁的时间差, 大于保护时间,则强制删除锁(防止锁死)
            long createTime = getLockValue(lockPrefix, key);
            if ((currentTime - createTime) > (expire * 1000 + protectTime)) {
                count++;
                if (count > MAX_RETRY_COUNT) {
                    return false;
                }
                System.out.print("==================delete lock");
                RedisUtils.delLock(lockPrefix + key);
                return getLock(annotationArgs, count, currentTime);
            }
            return false;
        }
    }

    /**
     * 删除锁
     */
    private void delLock(Map<String, Object> annotationArgs) {
        String lockPrefix = (String) annotationArgs.get(LOCK_PRE_FIX);
        String key = (String) annotationArgs.get(LOCK_KEY);
        RedisUtils.delLock(lockPrefix + key);
    }

    /**
     * 获取锁参数
     */
    private Map<String, Object> getAnnotationArgs(ProceedingJoinPoint proceeding) {
        Class target = proceeding.getTarget().getClass();
        Method[] methods = target.getMethods();
        String methodName = proceeding.getSignature().getName();
        Map<String, Object> result = new HashMap<>();
        for (Method method : methods) {
            if (method.getName().equals(methodName)) {
                RedisLock redisLock = method.getAnnotation(RedisLock.class);
                result.put(LOCK_PRE_FIX, redisLock.prefix());
                result.put(LOCK_KEY, redisLock.key());
                result.put(TIME_OUT, redisLock.timeout());
                result.put(PROTECT_TIME, redisLock.protectTime());
            }
        }
        return result;
    }

    /**
     * 查询锁
     *
     * @return 写锁时间
     */
    private long getLockValue(String prefix, String key) {
        Date value = RedisUtils.get(prefix + key, null);
        if (value != null) {
            return value.getTime();
        }
        return 0;
    }

}