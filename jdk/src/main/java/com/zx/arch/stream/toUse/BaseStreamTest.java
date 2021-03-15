package com.zx.arch.stream.toUse;

import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 流一般和集合对象一起使用，而不是基本类型。
 *              但是，为了方便处理最常用的三种基本类型——int，long，double，
 *              标准库提供三种基本类型的实现：IntStream,LongStream,DoubleStream.这些流称为基本类型流。
 *              仅提供部分基本类型，主要是因为包装基本类型有一定开销以及其他基本类型一般不常用
 **/
public class BaseStreamTest {

    /**
     * 1、创建基本类型流
     */
    public void a(){
        // 方式一、Arrays.stream()
        int[] integers = new int[] {20, 98, 12, 7, 35};
        int min = Arrays.stream(integers)
                .min()
                .getAsInt(); // returns 7

        // 方式二、IntStream.of
        int max = IntStream.of(20, 98, 12, 7, 35)
                .max()
                .getAsInt(); // returns 98

        // 方式三、IntStream.range (生成步长为1的整数流),区别是range()方法不包括最后元素值，rangeClosed()包括。
        IntStream i1 = IntStream.range(1, 10);
        IntStream i2 = IntStream.rangeClosed(1, 10);

        // 方式四、mapToXxx 和 flatMapToXxx方法可以创建基本类型流。
        IntStream i3 = Stream.of("aa","bb","cc").mapToInt(String::length);

        // 方式五、java8新增2个default方法
        // public default IntStream codePoints() 产生由当前字符串中的所有Unicode码点构成的流
        // public default IntStream chars() 产生由当前字符串中的所有字符代码构成的流
        // 分别转换为以char和codepoint为单位的java stream.注意转换后为int类型的unicode编码.
        String sentence  = "\uD835\uDD46 is the set of octonions.";
        IntStream i4 = sentence.codePoints();
        IntStream i5 = sentence.chars();
        System.out.println(i4.count()); // 26
        System.out.println(i5.count()); // 27

        // 其他还有：@blog https://www.jianshu.com/p/461429a5edc9

    }

    /**
     * 1、操作基本类型流
     */
    public void b(){
        // 1.1 转换基本类型至其对应的包装类型，可以使用boxed()方法：
        List<Integer> evenInts = IntStream.rangeClosed(1, 10)
                .filter(i -> i % 2 == 0)
                .boxed()
                .collect(Collectors.toList());

        // 1.2 这种方式作为for-each循环的优势是我们能利用其实现并行运算
        IntStream.rangeClosed(1, 5)
                .parallel()
                .forEach(System.out::println);

        // 其他的看 @blog https://www.jianshu.com/p/461429a5edc9
    }
}
