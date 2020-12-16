package com.zx.arch.stream.toUse;


import java.util.Arrays;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.IntStream;
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

        stream3.distinct().forEach(System.out::print);

        // 综上,如果会出现流中流的情况，那就要考虑使用flatMap()

    }

    /**
     * 1、filter    筛选满足条件的所有元素
     * 2、limit(n)  只要前n个元素
     * 3、skip(n)   丢弃前n个元素
     * 4、Stream.concat(stream1,stream2)   连接两个流
     * 5、distinct() 去重
     * 6、sorted    排序
       */
    public static void b(){
        // 1、筛选
        Stream stream = Stream.of(5,6,4,1,2,3);
        stream.filter(i-> Optional.of(i).get().equals(1)).forEach(System.out::print);System.out.println("\r\n");

        // 6、排序
        // Integer实现了Comparable,所以stream可以直接使用sorted进行排序
        Stream stream1 = Stream.of(5,6,4,1,2,3);
        stream1.sorted().forEach(System.out::print);System.out.println("\r\n");

        // 如果元素没有实现Comparable,那只能使用sorted(Comparator<? super T> comparator)
        // 或者如果元素自己实现的排序不是我们想要的,那也可以使用sorted(Comparator<? super T> comparator)
        Stream stream2 = Stream.of(5,6,4,1,2,3);
        stream2.sorted(Comparator.comparing(Object::toString).reversed()).forEach(System.out::print);

    }

    /**
     * jdk9
     * 1、takeWhile()    依次获取满足条件的元素，直到不满足条件为止结束获取
     * 2、dropWhile()    依次删除满足条件的元素，直到不满足条件为止结束删除
     */
    public static void c(){
        IntStream.of(12, 4, 3, 6, 8, 9).takeWhile(x -> x % 2 == 0).forEach(System.out::print);
        System.out.println("\r");
        IntStream.of(12, 4, 3, 6, 8, 9).dropWhile(x -> x % 2 == 0).forEach(System.out::print);
    }



    public static void main(String[] args) {
        b();
    }

}
