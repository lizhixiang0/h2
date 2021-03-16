package com.zx.arch.stream.toUse;

import com.google.errorprone.annotations.Var;
import org.checkerframework.checker.units.qual.A;

import java.lang.reflect.Array;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * @author lizx
 * @since 1.0.0
 * @description 介绍并行流以及使用注意事项
 * @blog 并发：一个人同时吃三个苹果。
 *       并行：三个人同时吃三个苹果。
 * @blog stream流的底层原理：https://blog.csdn.net/tyrroo/article/details/81390202
 **/
public class ParallelStreamTest {

    /**
     * 创建并行流
     */
    public static void a(){
        //1、Collection.parallelStream()
        //2、stream.parallel()
    }

    /**
     * 注意点：并行流得出的结果应该与顺序流的结果一致,在采用并行流收集元素到集合中时，最好调用collect方法，一定不要采用Foreach方法或者map方法
     * @blog "https://www.jianshu.com/p/51c1d4f1bf84
     * @blog 并行流遍历的线程安全问题：https://blog.csdn.net/yy1098029419/article/details/89452380
     * @note
     * 那么什么时候要用parallelStream呢？可以从以下三点入手考虑
     * 1、数据量是否大到需要并行？
     * 2、并行任务之间是否是独立的？是否会引起任何竞态条件？
     * 3、结果是否需要有序？
     */
    public static void b(){
        List<Integer> listOfIntegers = new ArrayList<>();
        for (int i = 0; i <100; i++) {
            listOfIntegers.add(i);
        }
        List<Integer> parallelStorage = new ArrayList<>() ;
        listOfIntegers
                .parallelStream()
                .filter(i->i%2==0)
                .forEach(parallelStorage::add);
        // 对于parallelStorage元素数量不固定的原因就是多线程有可能同时读取到相同的数组下标n同时赋值，这样就会出现元素缺失的问题了
        System.out.println((long) parallelStorage.size());
        parallelStorage.forEach(e -> System.out.print(e + " "));
    }



    public static void main(String[] args) {
        b();
    }






}
