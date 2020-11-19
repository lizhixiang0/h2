package com.zx.arch.jdk;

import com.google.common.collect.Lists;
import lombok.Data;

import java.lang.reflect.Array;
import java.nio.file.Files;
import java.util.LinkedList;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0   https://blog.csdn.net/IT_10/article/details/104747173
 * @description 比较Comparable接口和Comparator接口的使用和区别
 * @note 1、Comparable 是在集合内部定义的方法实现的排序,Comparator 是在集合外部实现的排序
 *                使用Comparator 可以不用改变类本身的代码而实现对类对象进行排序
 *
 *
 **/
public class CompareTest {

    private static class Phone {
        String name;

        public Phone(String name) {
            this.name = name;
        }
    }

    private static List list = new LinkedList();

    static {
        list.add(new Phone("小米"));
        list.add(new Phone("华为"));
        list.add(new Phone("苹果"));
        list.add(new Phone("锤子"));
    }

    private static void a(){

    }

}
