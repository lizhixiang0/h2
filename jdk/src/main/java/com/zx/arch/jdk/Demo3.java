package com.zx.arch.jdk;

import java.io.IOException;

/**
 * @author lizx
 * @since 1.0.0
 * @description 理解try-with-resources语句及示例
 * @blog "https://blog.csdn.net/zzti_erlie/article/details/108837882
 *       "http://www.zimug.com/java/java9%E6%94%B9%E8%BF%9Btry-with-resources%E8%AF%AD%E6%B3%95/.html
 **/
public class Demo3 {
    // 一个内部类
    static class MyResource implements AutoCloseable{

        public void open() throws IOException {
            System.out.println("resource is open!");
            throw new IOException("open() exception!");
        }

        @Override
        public void close() throws Exception {
            System.out.println("resource is close!");
            throw new IOException("close()  exception!");
        }
    }

    /**
     * jdk7之前
     */
    public static void a(){
        MyResource myResource = null;

        try{
            myResource = new MyResource();
            myResource.open();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                myResource.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * jdk7之后
     */
    public static void b(){
        try(MyResource myResource = new MyResource()){
            myResource.open();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args){
        a();
        // 说到底就是个语法糖,没有什么稀奇的。
    }
}
