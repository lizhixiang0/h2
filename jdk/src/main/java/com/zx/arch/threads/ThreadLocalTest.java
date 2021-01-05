package com.zx.arch.threads;

import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 1、ThreadLocal是什么?
 *              2、ThreadLocal怎么用?
 *              3、ThreadLocal源码分析?
 *              4、ThreadLocal内存泄漏问题?
 *
 * @blog  "https://baijiahao.baidu.com/s?id=1653790035315010634&wfr=spider&for=pc
 **/
public class ThreadLocalTest {
    public static void main(String[] args) {
        ThreadLocal<String> local = new ThreadLocal<>();
        Random random = new Random();
        IntStream.range(0,5).forEach(a->new Thread(()->{
            local.set(a +"    "+random.nextInt(10));
            System.out.println("线程和local值分别是"+local.get());
        }).start());
    }
}
