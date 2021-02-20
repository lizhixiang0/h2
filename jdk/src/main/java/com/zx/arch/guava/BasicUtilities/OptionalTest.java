package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.Optional;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;


import javax.swing.text.html.Option;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * @author lizx
 * @since 1.0.0
 * @description  通过Optional来合理使用或者避免null
 * @blog   "http://ifeve.com/google-guava-using-and-avoiding-null/"
 **/
@Slf4j
public class OptionalTest {
    private static HashMap map = Maps.newHashMap();

    private static void a(){
        map.put(null, "a");
        System.out.println(map.get("a"));

        map.put("a", null);
        System.out.println(map.get("a"));
        // Null的含糊语义让人很不舒服。Null很少可以明确地表示某种语义
        // 例如，Map.get(key)返回Null时，可能表示map中的值是null，亦或map中没有key对应的值。
        // Null可以表示失败、成功或几乎任何情况
    }

    private static void b() {
        // 首先,JDK1.8的新特性也包含一个Optional类  https://blog.csdn.net/weixin_43897590/article/details/108257129
        // 1、通过of()或者ofNullable()来创建Optional包装器对象
        // 传入的参数是null直接报NullPointerException,当然也可以使用ofNullable()方法，这样使用时需要调用isPresent()判断下
        java.util.Optional<String> possible = java.util.Optional.of(null);
        // 2、介绍map()      将optional中的对象 t 映射成另外一个对象 u (通常是调用对象t自己的方法生成u)，并将 u 存放到一个新的optional容器中。
        java.util.Optional<String> optional = java.util.Optional.of("aa").map(i ->i+"bb");
        // 2.1、flatMap()方法,map和flatMap均要求optional对象非空才执行mapper方法，二者均返回Optional对象。但是map会将计算结果封装为Optional对象，而flatMap则不是,一般使用flatMap来避免出现嵌套Optional
        // @blog https://blog.csdn.net/dengnanhua/article/details/101610604

        // 3、介绍orElse()   如果optional不为空，则直接返回optional中的对象；为null，则返回"s"这个默认值
        String  temp = possible.map(String::toString).orElse("S");
        // 4、介绍orElseGet(supplier) ,如果possible包装的是个null,就会调用supplier的get方法来计算默认值
        possible.orElseGet(String::new);
        // 5、介绍orElseThrow,如果possible包装的是个null,就会调用supplier的get方法来抛出异常
        possible.orElseThrow(IllegalAccessError::new);
        // 6、介绍ifPresent(Consumer) ,如果possible包装的不是个null就执行consumer的accept方法
        List list = Lists.newArrayList();
        possible.ifPresent(list::add);
        // 7、JDK9 介绍ifPresentOrElse(Consumer1,Consumer2) , 存在就执行Consumer1的accept,不存在就执行Consumer2的accept
        possible.ifPresentOrElse(list::add,()->log.error("cant find ..."));
        // 9、Optional直接转化成流，stream方法会将Optional转化成stream流，这个方法配合stream.flatMap有奇效
        java.util.Optional.of(list).stream();
        // 10、介绍empty()表示空值
        java.util.Optional.empty();
    }

    private static void e() {
        // jdk还提供了Objects.requireNonNull()来判断参数是否为null,Optional类好的一点是可以自定义报错信息
        Objects.requireNonNull(null,"The variable is null");
        // 如果给定参数为null ,可以返回默认值
        Objects.requireNonNullElse(null,null);

        // 支持以下面这种方式提供报错信息，以后再写这样的好处
        Supplier<String> messageSupplier = () -> "The variable is null";
        Objects.requireNonNull(null,messageSupplier);


    }

    private static void c(){
        // 下面这个是Guava的Optional类 ,我们暂时用fromNullable()方法,不会直接报错.
        Optional<String> possible = Optional.fromNullable("S");
        if(possible.isPresent()) {
            String temp = Optional.fromNullable(possible.get().toLowerCase()).or("d");
            System.out.println(temp);
        }
    }

    public static void main(String[] args) {
        // 两者区别:https://blog.csdn.net/qq_42105629/article/details/102458804
        // 实战:https://blog.csdn.net/y_k_y/article/details/84633143
        e();
    }
}
