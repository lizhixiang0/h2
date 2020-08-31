package com.zx.arch.storage;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


public interface VasSharedInfoStorage {
    void clearAll();

    void clearByKey(String group, String key);

    Object get(String group, String key);

    void put(String group, String key, Object object);

    boolean needRefreshGlobal();
}