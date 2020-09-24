package com.zx.arch.guava.collections;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.Lists;

import java.awt.*;
import java.util.Collections;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @blog "http://ifeve.com/google-guava-immutablecollections/
 * @description
 *              ���ɱ伯�ϣ�����˼�����˵�����ǲ��ɱ��޸ĵġ����ϵ��������ڴ�����ʱ���ṩ���������������������ж����ɸı䡣
 *              ΪʲôҪ��immutable����
 *              �̰߳�ȫ�ģ�immutable�����ڶ��߳��°�ȫ
 *              ����Ҫ֧�ֿɱ���, ���Ծ�����ʡ�ռ��ʱ��Ŀ���. ���еĲ��ɱ伯��ʵ�ֶ��ȿɱ伯�ϸ�����Ч�������ڴ�
 *              ���Ա�ʹ��Ϊһ������������������δ��Ҳ�Ǳ��ֲ���ġ�
 **/
public class UnmodifiableListTest {

    private static List<String> list= Lists.newArrayList();
    static{
        list.add("a");
        list.add("b");
        list.add("c");
    }
    /**
     * ���ȣ�JDKҲ�жԲ��ɱ伯�ϵ�֧��
     */
    public static void a(){
        List<String> unmodifiableList= Collections.unmodifiableList(list);
        System.out.println(unmodifiableList);
        // ����ԭ���ϻᵼ�²��ɱ伯�Ϸ����仯,��ʱ�����ſ����ԭ���ϻᵼ�²��ɱ伯�ϲ���ȫ
        list.add("baby");
        System.out.println("list add a item after unmodifiableList:"+unmodifiableList);

        unmodifiableList.add("bb");
        System.out.println("unmodifiableList add a item after list:"+unmodifiableList);
    }

    /**
     * guavaʵ�ֵĲ��ɱ伯��
     * ������ʽ������:
     * ����1����copyOf����, Ʃ��, ImmutableSet.copyOf(set)
     * ����2��ʹ��of������Ʃ��,ImmutableMap.of("a", 1, "b", 2)
     * ����3��ʹ��Builder��
     */
    public static void b(){
        // immutableList ��һ���¶���,��ԭ��list�޹��ˡ�
        ImmutableList<String> immutableList=ImmutableList.copyOf(list);

        ImmutableSortedSet<String> imSortList=ImmutableSortedSet.of("a", "b", "c", "a", "d", "b");

        ImmutableSet<Color> imColorSet = ImmutableSet.<Color>builder()
                        .add(new Color(0, 255, 255))
                        .add(new Color(0, 191, 255))
                        .build();

        System.out.println("imColorSet:"+imColorSet);

    }



    public static void main(String[] args) {
        // ͨ��ʹ��Guava �� copyOf() ���� ���������ɱ伯��
        b();
    }
}
