package com.zx.arch.storage;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.concurrent.TimeUnit;

/**
 * @author admin
 * @description  Caffeine是使用Java8对Guava缓存的重写版本，在Spring Boot 2.0中将取代Guava。如果出现Caffeine，CaffeineCacheManager将会自动配置
 */
public class VasSharedInfoStorageLocalCache implements VasSharedInfoStorage {
    Cache<String, Object> caffeineCache;

    public VasSharedInfoStorageLocalCache() {
        this.caffeineCache = Caffeine.newBuilder().expireAfterWrite(3600L, TimeUnit.SECONDS).maximumSize(1000L).build();
    }

    @Override
    public void clearAll() {
        this.caffeineCache.invalidateAll();
    }

    @Override
    public void clearByKey(String group, String key) {
        this.caffeineCache.invalidate(this.getKey(group, key));
    }

    @Override
    public Object get(String group, String key) {
        return this.caffeineCache.getIfPresent(this.getKey(group, key));
    }

    @Override
    public void put(String group, String key, Object object) {
        this.caffeineCache.put(this.getKey(group, key), object);
    }

    @Override
    public boolean needRefreshGlobal() {
        return true;
    }

    private String getKey(String group, String key) {
        StringBuilder sb = new StringBuilder(group);
        sb.append(key);
        return sb.toString();
    }
}
