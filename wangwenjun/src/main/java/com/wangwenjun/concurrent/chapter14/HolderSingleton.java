package com.wangwenjun.concurrent.chapter14;

/**
 * @author lizx
 * @date 2021/12/22
 * @since
 * @desctipyion holder方式实现单例
 **/
public class HolderSingleton {
    /**
     * HolderSingleton中不放置instance的静态成员，而是将其放到静态内部类Holder中,当Holder被引用时触发类的初始化,其创建HolderSingleton实例
     * 的创建过程被收集到<clinit>方法，该方法是同步方法 ! 能保证多线程安全,并且类只会被加载一次！满足单例要求！
     */
    private static class Holder {
        private static HolderSingleton instance = new HolderSingleton();
    }

    public static HolderSingleton getInstance(){
        return Holder.instance;
    }
}
