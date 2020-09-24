package com.zx.arch.guava.collections;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.Lists;

import java.awt.*;
import java.util.Collections;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @blog "http://ifeve.com/google-guava-immutablecollections/
 * @description
 *              不可变集合，顾名思义就是说集合是不可被修改的。集合的数据项在创建的时候提供，并且在整个生命周期中都不可改变。
 *              为什么要用immutable对象？
 *              线程安全的：immutable对象在多线程下安全
 *              不需要支持可变性, 可以尽量节省空间和时间的开销. 所有的不可变集合实现都比可变集合更加有效的利用内存
 *              可以被使用为一个常量，并且期望在未来也是保持不变的。
 **/
public class UnmodifiableListTest {

    private static List<String> list= Lists.newArrayList();
    static{
        list.add("a");
        list.add("b");
        list.add("c");
    }
    /**
     * 首先，JDK也有对不可变集合的支持
     */
    public static void a(){
        List<String> unmodifiableList= Collections.unmodifiableList(list);
        System.out.println(unmodifiableList);
        // 操作原集合会导致不可变集合发生变化,此时不可信库操作原集合会导致不可变集合不安全
        list.add("baby");
        System.out.println("list add a item after unmodifiableList:"+unmodifiableList);

        unmodifiableList.add("bb");
        System.out.println("unmodifiableList add a item after list:"+unmodifiableList);
    }

    /**
     * guava实现的不可变集合
     * 创建方式有三种:
     * 　　1、用copyOf方法, 譬如, ImmutableSet.copyOf(set)
     * 　　2、使用of方法，譬如,ImmutableMap.of("a", 1, "b", 2)
     * 　　3、使用Builder类
     */
    public static void b(){
        // immutableList 是一个新对象,和原来list无关了。
        ImmutableList<String> immutableList=ImmutableList.copyOf(list);

        ImmutableSortedSet<String> imSortList=ImmutableSortedSet.of("a", "b", "c", "a", "d", "b");

        ImmutableSet<Color> imColorSet = ImmutableSet.<Color>builder()
                        .add(new Color(0, 255, 255))
                        .add(new Color(0, 191, 255))
                        .build();

        System.out.println("imColorSet:"+imColorSet);

    }



    public static void main(String[] args) {
        // 通常使用Guava 的 copyOf() 方法 来构建不可变集合
        b();
    }
}
