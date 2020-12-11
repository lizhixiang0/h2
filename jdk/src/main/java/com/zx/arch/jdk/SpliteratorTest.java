package com.zx.arch.jdk;

import java.util.ArrayList;
import java.util.List;
import java.util.Spliterator;

/**
 * @author lizx
 * @since 1.0.0
 * @description  认识可分割迭代Spliterator
 * @blog  "https://blog.csdn.net/weixin_44245828/article/details/109748173
 *
 **/
public class SpliteratorTest {

    private static List list = new ArrayList();
    static {
        list.add(1);
        list.add(2);
        list.add(3);
        list.add(4);
        list.add(5);
        list.add(6);
    }

    /**
     *  初步了解Spliterator接口的常用方法
     */
    private static void a(){
        Spliterator spliterator = list.spliterator();
        // 1、将原来的spliterator平分成两个
        Spliterator spliterator1 = spliterator.trySplit();
        // 2、tryAdvance(Action action) 判断是否有元素还存在,存在返回true并且执行action来操作当前元素,不存在返回false
        spliterator1.tryAdvance(System.out::println);
        // 3、forEachRemaing(Action action)   对剩下的元素都执行action
        spliterator.forEachRemaining(System.out::println);
        // 4、hasCharacteristics() 对被分割的集合（分割器）是否拥有哪个特点进行判断
        if(spliterator1.hasCharacteristics(Spliterator.ORDERED)){
            System.out.println("ORDERED");
        }
        if(spliterator1.hasCharacteristics(Spliterator.SIZED)){
            System.out.println("SIZED");
        }
        // 5、返回集合的特征(多个值的or运算)。通过判断集合的特征，可以更好的做运算
        // 十六进制进行or运算 https://zhidao.baidu.com/question/526802683453856405.html
        int characteristics = spliterator1.characteristics();
        System.out.println(characteristics);

        // 6、估算还有多少元素没有被action(如果具备SIZED特性那返回的就是准确值),在元素数不尽或很难计算或者不知道的时候返回Long.MAX_VALUE
        long l1 = spliterator1.estimateSize();
        System.out.println(l1);

        // 7、如果分割器（被分割的集合）具备Spliterator.SIZED的特性，则返回estimateSize()的结果,否则返回-1
        long l2 = spliterator1.getExactSizeIfKnown();
        System.out.println(l2);
    }


    /**
     * Spliterator的四个子接口介绍,理解不了
     */
    public static void b(){
    }

    /**
     * Spliterator用法实例
     */
    public static void c(){

    }

    /**
     * https://www.cnblogs.com/nevermorewang/p/9368431.html
     * https://blog.csdn.net/lh513828570/article/details/56673804
     * @param args
     */
    public static void main(String[] args) {
        a();
    }

}
