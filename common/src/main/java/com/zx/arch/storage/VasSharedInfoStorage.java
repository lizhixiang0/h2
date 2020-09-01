package com.zx.arch.storage;


/**
 * @author admin
 * @ VAS共享信息库
 */
public interface VasSharedInfoStorage {
    void clearAll();

    void clearByKey(String group, String key);

    Object get(String group, String key);

    void put(String group, String key, Object object);

    boolean needRefreshGlobal();
}