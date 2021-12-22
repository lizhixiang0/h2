package com.wangwenjun.concurrent.chapter14;

/**
 * Holder 单例模式
 * @author admin
 * @description  改造后的枚举单例模式，支持懒加载
 */
public class EnumSingleton2 {

    private EnumSingleton2(){
        System.out.println("EnumSingleton2");
    }

    public static void method(){
        System.out.println("method");
    }

    private enum EnumHolder {
        INSTANCE;

        private EnumSingleton2 instance;

        EnumHolder() {
            this.instance = new EnumSingleton2();
        }

        private EnumSingleton2 getSingleton()
        {
            return instance;
        }
    }

    public static EnumSingleton2 getInstance()
    {
        return EnumHolder.INSTANCE.getSingleton();
    }
}