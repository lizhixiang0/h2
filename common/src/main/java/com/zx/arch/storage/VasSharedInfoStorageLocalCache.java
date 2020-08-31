package com.zx.arch.storage;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.concurrent.TimeUnit;

/**
 * @author admin
 * @description  使用caffeine进行本地缓存
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
