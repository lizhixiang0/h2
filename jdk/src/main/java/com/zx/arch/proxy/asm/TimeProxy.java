package com.zx.arch.proxy.asm;

/**
 * 坦克的代理方法
 * @author lizx
 * @since 1.0.0
 **/
public class TimeProxy {
    public static void before() {
        System.out.println("... before ...");
    }
    public static void after() {
        System.out.println("... after ...");
    }
}
