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
 * @description  ͨ��Optional������ʹ�û��߱���null
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
        // Null�ĺ����������˺ܲ������Null���ٿ�����ȷ�ر�ʾĳ������
        // ���磬Map.get(key)����Nullʱ�����ܱ�ʾmap�е�ֵ��null�����map��û��key��Ӧ��ֵ��
        // Null���Ա�ʾʧ�ܡ��ɹ��򼸺��κ����
    }

    private static void b() {
        // ����,JDK1.8��������Ҳ����һ��Optional��  https://blog.csdn.net/weixin_43897590/article/details/108257129
        // 1��ͨ��of()����ofNullable()������Optional��װ������
        // ����Ĳ�����nullֱ�ӱ�NullPointerException,��ȻҲ����ʹ��ofNullable()����������ʹ��ʱ��Ҫ����isPresent()�ж���
        java.util.Optional<String> possible = java.util.Optional.of(null);
        // 2������map()      ��optional�еĶ��� t ӳ�������һ������ u (ͨ���ǵ��ö���t�Լ��ķ�������u)������ u ��ŵ�һ���µ�optional�����С�
        java.util.Optional<String> optional = java.util.Optional.of("aa").map(i ->i+"bb");
        // 2.1��flatMap()����,map��flatMap��Ҫ��optional����ǿղ�ִ��mapper���������߾�����Optional���󡣵���map�Ὣ��������װΪOptional���󣬶�flatMap����,һ��ʹ��flatMap���������Ƕ��Optional
        // @blog https://blog.csdn.net/dengnanhua/article/details/101610604

        // 3������orElse()   ���optional��Ϊ�գ���ֱ�ӷ���optional�еĶ���Ϊnull���򷵻�"s"���Ĭ��ֵ
        String  temp = possible.map(String::toString).orElse("S");
        // 4������orElseGet(supplier) ,���possible��װ���Ǹ�null,�ͻ����supplier��get����������Ĭ��ֵ
        possible.orElseGet(String::new);
        // 5������orElseThrow,���possible��װ���Ǹ�null,�ͻ����supplier��get�������׳��쳣
        possible.orElseThrow(IllegalAccessError::new);
        // 6������ifPresent(Consumer) ,���possible��װ�Ĳ��Ǹ�null��ִ��consumer��accept����
        List list = Lists.newArrayList();
        possible.ifPresent(list::add);
        // 7��JDK9 ����ifPresentOrElse(Consumer1,Consumer2) , ���ھ�ִ��Consumer1��accept,�����ھ�ִ��Consumer2��accept
        possible.ifPresentOrElse(list::add,()->log.error("cant find ..."));
        // 9��Optionalֱ��ת��������stream�����ὫOptionalת����stream��������������stream.flatMap����Ч
        java.util.Optional.of(list).stream();
        // 10������empty()��ʾ��ֵ
        java.util.Optional.empty();
    }

    private static void e() {
        // jdk���ṩ��Objects.requireNonNull()���жϲ����Ƿ�Ϊnull,Optional��õ�һ���ǿ����Զ��屨����Ϣ
        Objects.requireNonNull(null,"The variable is null");
        // �����������Ϊnull ,���Է���Ĭ��ֵ
        Objects.requireNonNullElse(null,null);

        // ֧�����������ַ�ʽ�ṩ������Ϣ���Ժ���д�����ĺô�
        Supplier<String> messageSupplier = () -> "The variable is null";
        Objects.requireNonNull(null,messageSupplier);


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
        e();
    }
}
