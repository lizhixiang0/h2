package com.zx.arch.stream.toUse;


import java.util.*;
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
     * 3、peek()
     * 补充:深入理解map和flatMap的区别 https://blog.csdn.net/qdmoment/article/details/88990154
     * 补充:深入理解map和peek的区别 https://blog.csdn.net/tckt75433/article/details/81510743
     */
    public static void a(){
        //需求:给定单词列表["Hello","World"],返回列表["H","e","l", "o","W","r","d"],
        final String[] strings = {"HELLO","WORLD"};
        //下面两种方式都能将数组转化成stream流!!!当然推荐用第二种!直接将数组放到of()里去
        Stream<String[]> streamA = Arrays.asList(strings).stream().map(str -> str.split(""));
        Stream<String[]> streamB  = Stream.of(strings).map(str -> str.split(""));


        // 使用map对流里的的元素进行处理，操作元素，改变的是元素类型或值，元素数量不变
        Stream<Stream<String>> stream2 = streamA.map(i->Arrays.stream(i));


        // 使用flatMap对流中的元素进行处理，除了操纵元素,如果操纵元素时将元素也变为流类型，那flatMap会自动将所有流元素合并成一个
        // 所以，如果出现流中所有元素也都是流，那就要考虑使用flatMap()使它扁平化
        // 从另一种角度上说，使用了它，就是使用了双重for循环。
        Stream<String> stream3 = streamB.flatMap(str -> Arrays.stream(str));
        stream3.distinct().forEach(System.out::print);

        // peek并不是对流中数据进行处理!而是会将流中数据进行一个外部展示，流中数据没啥变化
        // 而map是对流中数据进行处理,必须是能改变流中元素,所以不能用streamA.map(System.out::println);
        streamA.peek(System.out::println);

    }


    /**
     * 约简操作：会将流约简成可以在程序中使用的非流值
     * max()  返回Optional(最大值)
     * min()  返回Optional(最小值)
     * findFirst() 一般与filter()联合使用,返回Optional(第一个匹配的)
     * findAny()   一般与filter()还有parallel()联合使用 ,返回Optional(只要有匹配的，随便返回那个元素)
     * anyMatch()  一般与parallel()联合使用， 只要有匹配一个就返回true
     * allMatch()  一般与parallel()联合使用,  都匹配返回true
     * noneMatch() 一般与parallel()联合使用,  都不匹配返回true
     */
    public static void b(){
        OptionalInt optionalInt = IntStream.of(1,2,3,4,2,2).parallel().filter(i->i==2).findAny();
        System.out.println(optionalInt.getAsInt());

        Boolean isAnyMatch = IntStream.of(1,2,3,4,2,2).parallel().anyMatch(i->i==2);
        Boolean isAllMatch = IntStream.of(1,2,3,4,2,2).parallel().allMatch(i->i==2);
        Boolean isNoneMatch = IntStream.of(1,2,3,4,2,2).parallel().noneMatch(i->i==2);
        System.out.println(isAnyMatch);
        System.out.println(isAllMatch);
        System.out.println(isNoneMatch);

    }

    /**
     * 1、filter    筛选满足条件的所有元素
     * 2、limit(n)  只要前n个元素
     * 3、skip(n)   丢弃前n个元素
     * 4、Stream.concat(stream1,stream2)   连接两个流
     * 5、distinct() 去重
     * 6、sorted    排序
       */
    public static void c(){
        // 1、筛选
        // filter里面的谓词参数与元素类型有关,比如如果是int基本类型可以直接用== ,如果是引用类型则使用equals() ,如果没注明使用IntStream，那Stream默认存储的都是对象
        Stream stream = Stream.of(5,6,4,1,2,3);
        stream.filter(i-> i.equals(2)).forEach(System.out::print);System.out.println("\r\n");

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
    public static void d(){
        IntStream.of(12, 4, 3, 6, 8, 9).takeWhile(x -> x % 2 == 0).forEach(System.out::print);
        System.out.println("\r");
        IntStream.of(12, 4, 3, 6, 8, 9).dropWhile(x -> x % 2 == 0).forEach(System.out::print);
    }






    public static void main(String[] args) {
        b();
    }

}
