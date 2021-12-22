package com.wangwenjun.concurrent.chapter14;

/**
 * @author lizx
 * @date 2021/12/22
 * @since  枚举类单例模式 ,缺点是EnumSingleton类一加载就会实例化INSTANCE
 **/
public enum EnumSingleton {
    INSTANCE;
    EnumSingleton(){
        System.out.println("EnumSingleton");
    }

    public static void method(){
        System.out.println("method");
    }

    public static EnumSingleton getInstance(){
        return INSTANCE;
    }
}
