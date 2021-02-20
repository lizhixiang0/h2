package com.zx.arch.stream.toUse;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * @author lizx
 * @since 1.0.0
 * @decsription 如何创建、使用、关闭stream流
 **/
public class CreateStream {
    /**
     * 数据准备
     */
    private static String[] strings;
    private static List list;
    private static Stream stream;
    /**
     * 1、了解\\PL是啥意思(非.字母)  https://blog.csdn.net/CelLew/article/details/81362977
     * 2、Pattern的预编译功能 https://blog.csdn.net/weixin_44259720/article/details/102806050
     */
    private static final Pattern pattern  = Pattern.compile("\\PL+");

    static {
        strings = new String[]{"a","b","a"};
        list = new ArrayList();
        list.add(1);
        list.add(2);
    }

    /**
     *  通常情况下创建Stream的方式
     * @blog "https://blog.csdn.net/qq_38718258/article/details/104696658
     */
    private static void createStream(){
        // 1、使用静态的of()可以直接对字符串创建stream ,如果参数是null 则报错,如果需要为null时不报错，则使用ofNullable()
        stream = Stream.of("a","b","a");
        //  这个方法结合flatMap可以快速排除为null的元素
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
        String content = " hello44 world";
        // 分割开后第一个元素为"",所以需要skip跳过
        stream = pattern.splitAsStream(content).skip(1);
        stream.forEach(System.out::println);
        //扫描器也可以从字符串获取单词，但它默认是以空格作为分隔符
        stream=new Scanner(content).tokens();

        // 2、Files.lines(Path)会返回一个包含文件所有行的stream
        // 这边记得Path是怎么构造的。
        stream=Files.lines(Paths.get(CreateStream.class.getResource("/static/test.txt").toURI()));
        stream.forEach(System.out::println);

        // 3、iterator对象可以转化成stream流,先将迭代器转变成分割器,然后再将分割器转换成stream流
        Iterator iterator =list.iterator();
        stream = StreamSupport.stream(Spliterators.spliteratorUnknownSize(iterator,Spliterator.ORDERED),false);
        stream = StreamSupport.stream(Spliterators.spliteratorUnknownSize(Paths.get(CreateStream.class.getResource("/static/test.txt").toURI()).iterator(),Spliterator.ORDERED),false);
        stream.forEach(System.out::println);
        // 4、iterable对象可以转化成stream流,这里说明下.list实现了iterable接口，所以他算是iterable对象，
        // 其实iterable.iterator()即Iterator对象
        // iterable:可迭代的    Iterator:迭代器
        stream = StreamSupport.stream(list.spliterator(),false);
        stream = StreamSupport.stream(FileSystems.getDefault().getRootDirectories().spliterator(),false);
        stream.forEach(System.out::println);
    }

    /**
     *  使用stream的注意点
     *  1、创建流之后修改集合是允许的，虽然并不建议 ！但是不许一边操作流一边修改集合 ，这样是不允许的。
     */
    private static void useStream(){
        Stream stream = list.stream();
        list.add(3);
        stream.count();
        stream.forEach(i-> list.add(4));
    }

    public static void main(String[] args) throws IOException, URISyntaxException {
        createStream2();
    }

}
