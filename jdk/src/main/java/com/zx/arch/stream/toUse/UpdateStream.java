package com.zx.arch.stream.toUse;

import java.util.Arrays;
import java.util.stream.Stream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 操作stream流
 **/
public class UpdateStream {


    /**
     * 1、map()
     * 2、flatMap()
     * 补充:深入理解map和flatMap的区别 https://blog.csdn.net/qdmoment/article/details/88990154
     */
    public static void a(){
        //需求:给定单词列表["Hello","World"],返回列表["H","e","l", "o","W","r","d"],
        final String[] strings = {"HELLO","WORLD"};


        Stream<String[]> streamA = Arrays.asList(strings).stream().map(str -> str.split(""));

        // 使用map对流里的的元素进行处理，操作元素，改变的是元素类型或值，元素数量不变
        Stream<Stream<String>> stream2 = streamA.map(i->Arrays.stream(i));


        Stream<String[]> streamB = Arrays.asList(strings).stream().map(str -> str.split(""));
        // 使用flatMap对流中的元素进行处理，除了操纵元素,如果操纵元素时将元素也变为流类型，那flatMap会自动将所有流元素合并成一个
        Stream<String> stream3 = streamB.flatMap(str -> Arrays.stream(str));

        stream3.forEach(System.out::print);

        // 综上,如果会出现流中流的情况，那就要考虑使用flatMap()

    }

    public static void main(String[] args) {
        a();
    }

}
