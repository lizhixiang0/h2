package com.zx.arch.stream.toUse;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Pattern;
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
    /**
     * 1、了解\\PL是啥意思(以非字母作为分隔符)  https://blog.csdn.net/CelLew/article/details/81362977
     * 2、Pattern的预编译功能 https://blog.csdn.net/weixin_44259720/article/details/102806050
     */
    private static final Pattern pattern  = Pattern.compile("\\PL+");

    static {
        strings = new String[]{"a","b","a"};
        list = Arrays.asList(strings);
    }

    /**
     *  通常情况下创建Stream的方式
     * @blog "https://blog.csdn.net/qq_38718258/article/details/104696658
     */
    private static void createStream(){
        // 1、使用静态的of()可以直接对字符串创建stream ,如果参数是null 则报错,如果需要为null时不报错，则使用ofNullable()
        stream = Stream.of("a","b","a");
        stream  = Stream.ofNullable(null);

        // 2、集合工具类Arrays也可以创建stream流(并且只取数组中一部分元素)
        stream = Arrays.stream(strings,1,2);

        // 3、大部分集合类可以直接创建stream或者并行stream(一边过滤一边计数)
        long a = list.parallelStream().filter(i-> StringUtils.equals(i.toString(),"a")).distinct().count();

        // 4、创建一个不包含任何元素的流,个人觉得它替代了无参构造函数的作用
        stream = Stream.empty();

        // 5、创建无限流的两种方式generate和iterate,都可以用limit限制只需要3个,还可以用skip跳过一个，这样最后计数只有2个
        // "::"，简单来说是lambda表达式的简写,@blog https://www.cnblogs.com/yanlong300/p/9209243.html
        Stream.generate(UUID::randomUUID).limit(3).skip(1).count();
        // iterate方法比较好玩,有点像套娃,用方法包住种子
        Stream.iterate(BigInteger.ZERO,item->item.add(BigInteger.ONE)).limit(3);
    }

    /**
     *  其他情况下创建Stream的方式  ,这里的意思是不一定用得着
     */
    private static void createStream2() throws IOException, URISyntaxException {
        // 1、从字符串中获取单词流
        String content = "hello44 world";
        Stream<String> stream = pattern.splitAsStream(content);
        //扫描器也可以从字符串获取单词，但它默认是以空格作为分隔符
        stream=new Scanner(content).tokens();

        // 2、Files.lines(Path)会返回一个包含文件所有行的stream
        // 这边记得Path是怎么构造的。
        stream=Files.lines(Paths.get(Demo1.class.getResource("/static/test.txt").toURI()));
        stream.forEach(System.out::println);

    }

    /**
     *  使用stream的注意点
     *  1、
     */
    private static void useStream(){

    }





    public static void main(String[] args) throws IOException, URISyntaxException {
        useStream();
    }

}
