package com.zx.arch.jdk;

/**
 * @author lizx
 * @since 1.0.0
 * @测试接口继承接口
 * 接口不可以实现接口，实现就意味着实现方法。
 **/
public class InterfaceExtend {
    private  interface Demo1{
        /**
         * 测试
         * @param command
         */
        void a(Runnable command);
    }

    private  interface Demo2{
        /**
         * 测试
         * @param command
         */
        void a(Runnable command);
    }

    private  interface Demo12 extends Demo1 {
        @Override
        void a(Runnable var1);
    }

}


