package com.zx.arch.stream.toUse;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.nio.file.Path;
import java.time.Period;
import java.util.*;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 操作stream流
 **/
public class UpdateStream {


    /**
     * 1、map(i-> ?)   参数是mapper类型，将元素映射成其他样子
     * 2、flatMap(i->stream.of(i)) ，  注意看flatMap的参数，是一个mapper类型。将所有元素映射成流，然后统一扁平化
     * 3、peek()   peek是窥视的意思，即不改变流，只进行展示
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


        // 使用flatMap对流中的元素进行处理，将单个元素也变为流类型，那flatMap会自动将所有流元素合并成一个
        // 并且合并的时候会自动将空stream去掉。
        // 所以，如果出现流中所有元素也都是流，那就要考虑使用flatMap()使它扁平化
        // 从另一种角度上说，使用了它，就是使用了双重for循环。
        Stream<String> stream3 = streamB.flatMap(str -> Arrays.stream(str));
        stream3.distinct().forEach(System.out::print);

        // 最重要的一点是map可以改变返回值类型，而peek无法改变返回值类型，但peek可用来修改数据；
        // 注意： map 和peek 都有返回值为Stream ,且注意两者执行函数的时机不同
        // @blog https://www.jianshu.com/p/4fabc8a7abca
        // 下面是不会执行的，因为这两个方法都是中间操作,不是终止操作 @blog https://blog.csdn.net/weixin_26969967/article/details/113015509
        streamA.peek(System.out::println).map(str -> Arrays.stream(str));


    }


    /**
     * 约简操作：会将流约简成可以在程序中使用的非流值
     * 4、max()  返回Optional(最大值)
     * 5、min()  返回Optional(最小值)
     * 6、findFirst() 一般与filter()联合使用,返回Optional(第一个匹配的)
     * 7、findAny()   一般与filter()还有parallel()联合使用 ,返回Optional(只要有匹配的，随便返回那个元素)
     *
     * 8、anyMatch()  一般与parallel()联合使用， 只要有匹配一个就返回true
     * 9、allMatch()  一般与parallel()联合使用,  都匹配返回true
     * 10、noneMatch() 一般与parallel()联合使用,  都不匹配返回true
     *
     */
    public static void b(){

        int a = Stream.of(2,1,4,5,3).max(Integer::compare).get();
        int b = Stream.of(2,1,4,5,3).min(Integer::compare).get();

        System.out.println(a);
        System.out.println(b);

        OptionalInt optionalInt = IntStream.of(1,2,3,4,2,2).parallel().filter(i->i==2).findAny();
        System.out.println(optionalInt.getAsInt());

        Boolean isAnyMatch = IntStream.of(1,2,3,4,2,2).parallel().anyMatch(i->i==2);
        Boolean isAllMatch = IntStream.of(1,2,3,4,2,2).parallel().allMatch(i->i==2);
        Boolean isNoneMatch = IntStream.of(1,2,3,4,2,2).parallel().noneMatch(i->i==2);
        System.out.println(isAnyMatch);
        System.out.println(isAllMatch);
        System.out.println(isNoneMatch);
        //https://blog.csdn.net/qq_28410283/article/details/110533469

    }

    /**
     * 中间操作
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
        stream.filter(i-> i.equals(2)).forEach(System.out::print);
        System.out.println("\r\n");

        // 6、排序
        // Integer实现了Comparable,所以stream可以直接使用sorted进行排序
        Stream stream1 = Stream.of(5,6,4,1,2,3);
        stream1.sorted().forEach(System.out::print);
        System.out.println("\r\n");

        // 如果元素没有实现Comparable,那只能使用sorted(Comparator<? super T> comparator)
        // 或者如果元素自己实现的排序不是我们想要的,那也可以使用sorted(Comparator<? super T> comparator)
        Stream stream2 = Stream.of(5,6,4,1,2,3);
        stream2.sorted(Comparator.comparing(Object::toString).reversed()).forEach(System.out::print);

    }

    /**
     * 中间操作
     * jdk9
     * 1、takeWhile()    依次获取满足条件的元素，直到不满足条件为止结束获取
     * 2、dropWhile()    依次删除满足条件的元素，直到不满足条件为止结束删除
     */
    public static void d(){
        IntStream.of(12, 4, 3, 6, 8, 9).takeWhile(x -> x % 2 == 0).forEach(System.out::print);
        System.out.println("\r");
        IntStream.of(12, 4, 3, 6, 8, 9).dropWhile(x -> x % 2 == 0).forEach(System.out::print);
    }

    /**
     * 收集经过流处理后的数据
     *  stream.collect(Collectors.toList())
     */
    public static void collect(){
        Stream<Integer> stream = Stream.of(5,6,4,1,2,3);
        // 1、按任意顺序遍历元素
        stream.forEach(System.out::println);
        // 2、按流中顺序遍历元素
        stream.forEachOrdered(System.out::println);
        // 3、将流转化成数组，注意传入数组的正确类型
        stream.toArray(Integer[]::new);
        // 4、将流转化成迭代器
        Iterator<Integer> iterator = stream.iterator();
        // 5、使用Collectors收集器，将流转化成list集合
        List<Integer> list = stream.collect(Collectors.toList());
        // 6、使用Collectors收集器，将流转化成set集合
        Set<Integer> set = stream.collect(Collectors.toSet());
        // 7、可以使用Collectors.toCollection来控制集合的种类
        TreeSet<Integer> treeSet = stream.collect(Collectors.toCollection(TreeSet::new));
        // 8、可以使用Collectors.joining来连接流中所有字符串(可以添加分隔符),如果流对象不是字符串使用toString转换
        stream.map(Object::toString).collect(Collectors.joining(","));
        // 9、可以使用Collectors.summarizingInt来获取流结果的总和|数量|平均值|最大值|最小值
        double d = stream.map(Object::toString).collect(Collectors.summarizingInt(String::length)).getMax();
    }

    /**
     * 中间操作
     * 将流中元素收集到映射表中，也是使用收集器，但是这个比较特殊，所以单独拿出来
     *  stream.collect(Collectors.toMap)
     *
     *  补充：这里可以和并行流一起使用parallel().collect(Collectors.toConcurrentMap())
     */
    public static void map(){
        @Data
        @AllArgsConstructor
        class Person{
            String name;
            int age;
        }
        Stream<Person> stream = Stream.of(
                new Person("李白",12),
                new Person("杜甫",13),
                new Person("苏轼",14),
                new Person("王勃",14)
        );
        // 数据准备完毕
        // 1、以年龄为key,Person为value ,将元素放到一个Map中
        // Map<Integer, Person> map = stream.collect(Collectors.toMap(Person::getAge, Function.identity()));
        // 2、上面语句会报错IllegalStateException ,因为14岁的有两位,所以得加入第三个函数引元啦来处理特殊情况,即如果新元素产生的key在Map中已经出现过了，
        // 第三个参数定义处理方法,这个处理方法既可以是使用旧值或新值，也可以抛出异常
        // 第四个参数可以定义返回值类型，比如我们想要TreeMap ！！
        // @blog "https://www.cnblogs.com/ampl/p/10904306.html
        // Map<Integer, Person> map = stream.collect(Collectors.toMap(Person::getAge, Function.identity(), (existing, replacement) ->existing));
        Map<Integer, Person> map = stream.collect(Collectors.toMap(Person::getAge, Function.identity(), (existing, replacement) ->{throw new IllegalStateException();},TreeMap::new));

        //最后补充，如果Map<key,value>中的value是集合类型，那第三个参数可以对已有的集合和新集合做合并操作(这里使用Locale来帮助描述,例程的主要目的是收集给定国家的所有语言)
        Map<String,Set<String>> maps = Stream.of(Locale.getAvailableLocales())
                .collect(Collectors.toMap
                        (
                            Locale::getDisplayCountry,
                            l->Set.of(l.getDisplayLanguage()),
                            (a,b)-> {
                                Set<String> union = new HashSet<>(a);
                                union.addAll(b);
                                return union;
                            }
                        )
                );

    }

    /**
     * 将stream流中具有相同特性的的值 群聚成组
     */
    public static void  group(){
        Stream<Locale> stream = Stream.of(Locale.getAvailableLocales());
        //1、groupingBy将相同国家的local收集到一块,换成人则可以将相同岁数的人放到一起去。
        Map<String,List<Locale>> map = stream.collect(Collectors.groupingBy(Locale::getCountry));
        //  CN是中国的域名,有6种locale ,[bo_CN, yue_CN_#Hans粤语, zh_CN , ii_CN 彝语, zh_CN_#Hans, ug_CN 维吾尔语(中国)]
        List<Locale> locales = map.get("CN");
        //2、将local分为中国和其他国家两类，使用partitioningBy
        Map<Boolean,List<Locale>> map1 = stream.collect(Collectors.partitioningBy(l->l.getCountry().equals("CN")));
        List<Locale> china = map1.get(true);

        //3、如果想要返回的是集合而不是列表，那就加一个下游处理器：Collectors.toSet()
        Map<Boolean,Set<Locale>> map2 = stream.collect(Collectors.partitioningBy(l->l.getCountry().equals("CN"),Collectors.toSet()));
        //4、我们可以看到返回的<k,v>中v类型为Set<Locale>,而我们需要Set<String> ,这里可以使用Collectors.mapping,将函数应用到收集到的每个元素
        Map<Boolean,Set<String>> map5= stream.collect(Collectors.partitioningBy(l->l.getCountry().equals("CN"),Collectors.mapping(Locale::getDisplayLanguage,Collectors.toSet())));
        //5、我们可以使用Collectors.collectingAndThen,先返回为set,然后求set的大小
        Map<Boolean,Integer> map4 = stream.collect(Collectors.partitioningBy(l->l.getCountry().equals("CN"),Collectors.collectingAndThen(Collectors.toSet(),Set::size)));
        //6、也可以加数字收集器 Collectors.counting()，计算每个国家有多少个locale
        Map<String,Long> map3 = stream.collect(Collectors.groupingBy(Locale::getCountry,Collectors.counting()));
        //7、另外还有 Collectors.maxBy(Comparator.comparing(Person::getAge))、Collectors.minBy(),可以计算年纪最大的和年纪最小的
        //8、还有   Collectors.summingInt(Person::getAge) ,可以计算所有人岁数加起来多大
        //9、可以加Collectors.filtering(p->p.getAge()>20) ,只需要大于20岁的人


    }

    /**
     * 约简操作
     * reduce(BinaryOperator<T> accumulator);
     * accumulator是用于流中计算的机制,俗称累积器函数
     *
     */
    public static void  reduce(){
        //https://blog.csdn.net/shenhaiyushitiaoyu/article/details/84142618
        List<Integer> list = new ArrayList<>(){
            // {} 就是代码块,构造对象时自动执行
            {
                add(1);
                add(2);
                add(3);
            }
        };
        // 1、reduce((x, y) -> x + y)的作用是可以将流中所有元素累加起来,可以写成Integer::sum
        Optional<Integer> reduce = list.stream().reduce((x, y) -> x + y);
        System.out.println(reduce.get());

        // 2、第二种写法，给定一个起点值0,这样返回值就不用使用optional包起来
        Integer integer = list.stream().reduce(0, (x, y) -> x + y);
        System.out.println(integer);

        List<String> list1 = new ArrayList<>(){
            // {} 就是代码块,构造对象时自动执行
            {
                add("abc");
                add("abcd");
                add("abce");
            }
        };
        // 计算流中字符串元素的总长度，特殊在流中是string类型,而而累积结果是int类型，实际生产中我们是直接使用map将映射成整数再去求出结果，下面主要是为了演示reduce()
        // 第一个参数：起点值
        // 第二个参数：累积器函数，计算所有元素的长度累加
        // 第三个参数：组合器函数，在并行操作时会得到多个total值,这个函数用来累加这些total,可以写成Integer::sum
        Integer count = list1.stream().reduce(
                0,
                (total, word) -> total + word.length(),
                (total1, total2) -> total1 + total2
        );
        System.out.println(count);
    }

    public static void main(String[] args) {
       reduce();
    }

}
