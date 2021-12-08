package com.zx.arch.redis;


import com.zx.arch.spring.SpringContextHolder;
import org.apache.commons.lang3.BooleanUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.RedisCommands;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.util.Date;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * The type Redis utils.
 */
public class RedisUtils {
    private static final Logger logger = LoggerFactory.getLogger(RedisUtils.class);
    private static final StringRedisSerializer STR_SERIALIZER = new StringRedisSerializer();
    // 这里pax做了实现，我不想去拷贝了。太多了
    private static final RedisSerializer<Object> OBJ_SERIALIZER = new RedisSerializer() {
        @Override
        public byte[] serialize(Object o) throws SerializationException {
            return new byte[0];
        }

        @Override
        public Object deserialize(byte[] bytes) throws SerializationException {
            return null;
        }
    };


    /**
     * Call r.
     *
     * @param <R>          the type parameter
     * @param function     the function
     * @param defaultValue the default value
     * @return the r
     */
    public static <R> R call(Function<RedisCommands, R> function, R defaultValue) {
        RedisConnection connection = null;
        try {
            RedisConnectionFactory connectionFactory = SpringContextHolder.getBean(RedisConnectionFactory.class);
            connection = connectionFactory.getConnection();
            return function.apply(connection);
        } catch (Exception e) {
            logger.warn("Unable to call redis: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
        return defaultValue;
    }

    /**
     * Call.
     *
     * @param function the function
     */
    public static void call(Consumer<RedisCommands> function) {
        RedisConnection connection = null;
        try {
            RedisConnectionFactory connectionFactory = SpringContextHolder.getBean(RedisConnectionFactory.class);
            connection = connectionFactory.getConnection();
            function.accept(connection);
        } catch (Exception e) {
            logger.warn("Unable to call redis: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

    /**
     * Sets nx.
     *
     * @param <T>     the type parameter
     * @param key     the key
     * @param value   the value
     * @param timeout the timeout, seconds
     * @return the nx
     */
    public static <T> void setNX(String key, T value, long timeout) {
        Boolean flag = call(redis -> redis.setNX(RedisUtils.serializeStr(key), RedisUtils.serializeObj(value)), false);
        if (BooleanUtils.isTrue(flag)) {
            //设置过期时间
            RedisUtils.call(redis -> redis.expire(RedisUtils.serializeStr(key), timeout), null);
        }
        call(redis -> redis.exists());
    }

    /**
     * Set boolean.
     *
     * @param <T>     the type parameter
     * @param key     the key
     * @param value   the value
     * @param timeout the timeout
     * @return the boolean
     */
    public static <T> void set(String key, T value, long timeout) {
        call(redis -> redis.set(RedisUtils.serializeStr(key), RedisUtils.serializeObj(value)));
        call(redis -> redis.expire(RedisUtils.serializeStr(key), timeout));
    }

    /**
     * Get string.
     *
     * @param <T>          the type parameter
     * @param key          the key
     * @param defaultValue the default value
     * @return the string
     */
    public static <T> T get(String key, T defaultValue) {
        byte[] result = call(redis -> redis.get(RedisUtils.serializeStr(key)), RedisUtils.serializeObj(defaultValue));
        if (result != null) {
            return (T) RedisUtils.deserializeObj(result);
        }
        return null;
    }

    /**
     * H get t.
     *
     * @param <T>          the type parameter
     * @param key          the key
     * @param field        the field
     * @param defaultValue the default value
     * @return the t
     */
    public static <T> T hGet(String key, String field, T defaultValue) {
        byte[] result = call(redis -> redis.hGet(RedisUtils.serializeStr(key), RedisUtils.serializeStr(field)), RedisUtils.serializeObj(defaultValue));
        if (result != null) {
            return (T) RedisUtils.deserializeObj(result);
        }
        return null;
    }

    /**
     * H set.
     *
     * @param <T>   the type parameter
     * @param key   the key
     * @param field the field
     * @param value the value
     */
    public static <T> void hSet(String key, String field, T value) {
        call(redis -> redis.hSet(RedisUtils.serializeStr(key), RedisUtils.serializeStr(field), RedisUtils.serializeObj(value)));
    }

    /**
     * H del.
     *
     * @param key   the key
     * @param field the field
     */
    public static void hDel(String key, String field) {
        RedisUtils.call(redis -> redis.hDel(RedisUtils.serializeStr(key), RedisUtils.serializeStr(field)));
    }

    /**
     * Exists boolean.
     *
     * @param key the key
     * @return the boolean
     */
    public static boolean exists(String key) {
        return call(redis -> redis.exists(RedisUtils.serializeStr(key)), false);
    }

    /**
     * 加分布式锁，锁的有效期默认一个小时
     *
     * @param key the key
     * @return the boolean
     */
    public static boolean tryLock(String key) {
        return tryLock(key, 3600);
    }

    /**
     * 加分布式锁
     *
     * @param key     the key
     * @param timeout the timeout, seconds
     * @return the boolean
     */
    public static boolean tryLock(String key, long timeout) {
        Boolean flag = call(redis -> redis.setNX(RedisUtils.serializeStr(key), RedisUtils.serializeObj(new Date())), false);
        if (flag) {
            //设置过期时间
            RedisUtils.call(redis -> redis.expire(RedisUtils.serializeStr(key), timeout), null);
        }
        return flag;
    }

    /**
     * 删除锁
     *
     * @param key the key
     */
    public static void delLock(String key) {
        RedisUtils.call(redis -> redis.del(RedisUtils.serializeStr(key)), false);
    }

    /**
     * Serialize str byte [ ].
     *
     * @param str the object
     * @return the byte [ ]
     */
    public static byte[] serializeStr(String str) {
        return STR_SERIALIZER.serialize(str);
    }

    /**
     * Deserialize str string.
     *
     * @param bytes the bytes
     * @return the string
     */
    public static String deserializeStr(byte[] bytes) {
        return STR_SERIALIZER.deserialize(bytes);
    }

    /**
     * Serialize obj byte [ ].
     *
     * @param object the object
     * @return the byte [ ]
     */
    public static byte[] serializeObj(Object object) {
        return OBJ_SERIALIZER.serialize(object);
    }

    /**
     * Deserialize obj object.
     *
     * @param bytes the bytes
     * @return the object
     */
    public static Object deserializeObj(byte[] bytes) {
        return OBJ_SERIALIZER.deserialize(bytes);
    }
}
