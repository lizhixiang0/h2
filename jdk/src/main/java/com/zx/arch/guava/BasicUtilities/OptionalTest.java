package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.Optional;
import com.google.common.collect.Maps;


import java.util.HashMap;
import java.util.Objects;

/**
 * @author lizx
 * @since 1.0.0
 * @description  ͨ��Optional������ʹ�û��߱���null
 * @blog   "http://ifeve.com/google-guava-using-and-avoiding-null/"
 **/
public class OptionalTest {
    private static HashMap map = Maps.newHashMap();

    private static void a(){
        map.put(null, "a");
        System.out.println(map.get("a"));

        map.put("a", null);
        System.out.println(map.get("a"));
        // Null�ĺ����������˺ܲ������Null���ٿ�����ȷ�ر�ʾĳ������
        // ���磬Map.get(key)����Nullʱ�����ܱ�ʾmap�е�ֵ��null�����map��û��key��Ӧ��ֵ��
        // Null���Ա�ʾʧ�ܡ��ɹ��򼸺��κ����
    }

    private static void b() {
        // ����,JDK1.8��������Ҳ����һ��Optional��  https://blog.csdn.net/weixin_43897590/article/details/108257129
        // 1������Ĳ�����nullֱ�ӱ�NullPointerException,��ȻҲ����ʹ��ofNullable()����������ʹ��ʱ��Ҫ����isPresent()�ж���
        java.util.Optional<String> possible = java.util.Optional.of(null);
        // 2������map()      ��optional�еĶ��� t ӳ�������һ������ u (ͨ���ǵ���t�ķ�������u)������ u ��ŵ�һ���µ�optional�����С�
        // 3������orElse()   ���optional��Ϊ�գ���ֱ�ӷ���optional�еĶ���Ϊnull���򷵻�"s"���Ĭ��ֵ
        // 4������orElseGet() ,"https://www.jianshu.com/p/790f7c185d3e
        String  temp = possible.map(String::toString).orElse("S");
        System.out.println(temp);
    }

    private static void c(){
        // ���������Guava��Optional�� ,������ʱ��fromNullable()����,����ֱ�ӱ���.
        Optional<String> possible = Optional.fromNullable("S");
        if(possible.isPresent()) {
            String temp = Optional.fromNullable(possible.get().toLowerCase()).or("d");
            System.out.println(temp);
        }
    }

    public static void main(String[] args) {
        // ��������:https://blog.csdn.net/qq_42105629/article/details/102458804
        // ʵս:https://blog.csdn.net/y_k_y/article/details/84633143
        // ���ֻ��˵��ֹ����Ϊnull,ObjectsҲ�ṩ��һ��
        Objects.requireNonNull(null);
    }
}
