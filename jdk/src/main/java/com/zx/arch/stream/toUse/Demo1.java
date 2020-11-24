package com.zx.arch.stream.toUse;

import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * @author lizx
 * @since 1.0.0
 * @decsription 如何创建、使用、关闭stream流
 **/
public class Demo1 {
    /**
     * 数据准备
     */
    private static String[] strings;
    private static List list;
    private static Stream stream;

    static {
        strings = new String[]{"a","b","a"};
        list = Arrays.asList(strings);
    }

    /**
     *  创建Stream的方式
     * @blog "https://blog.csdn.net/qq_38718258/article/details/104696658
     */
    private static void createStream(){

        // 1、使用静态的of()可以直接对字符串创建stream
        stream = Stream.of("a","b","a");

        // 2、集合工具类Arrays也可以创建stream流(并且只取数组中一部分元素)
        stream = Arrays.stream(strings,1,2);

        // 3、大部分集合类可以直接创建stream或者并行stream(一边过滤一边计数)
        long a = list.parallelStream().filter(i-> StringUtils.equals(i.toString(),"a")).count();

        // 4、创建一个不包含任何元素的流,个人觉得它替代了无参构造函数的作用
        stream = Stream.empty();

        // 5、创建无限流,也可以用limit限制只需要3个,还可以用skip跳过一个，这样最后计数只有2个
        // "::"，简单来说是lambda表达式的简写
        // @blog https://www.cnblogs.com/yanlong300/p/9209243.html
        long b =  Stream.generate(UUID::randomUUID).limit(3).skip(1).count();


    }

    public static void main(String[] args) {

    }

}
