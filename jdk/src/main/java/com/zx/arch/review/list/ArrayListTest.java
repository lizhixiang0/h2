package com.zx.arch.review.list;

import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description ʹ��ArrayList��һЩע���
 **/
@Slf4j
public class ArrayListTest {

    private static List<Integer> array = Lists.newArrayList();
    static {
        array.add(1);
        array.add(2);
        array.add(3);
        array.add(4);
        array.add(5);
    }

    /**
     *  ��ƽʱ����Ҫȡ��������һ��������ʱ��ͨ����ʹ��subList,����array���ڲ��࣬Ҳ���Կ���array��ӳ�䣨��ͼ��
     */
    public static void a(){
        List subList = array.subList(0,2);
        System.out.println(subList.size());
        //1�� subListɾ��һ��Ԫ��,arrayҲ����һ��Ԫ��,����˵sublist��array��һ����ͼ
        subList.remove(1);
        System.out.println(array.size());

        //2��subList��Ϊarray���ڲ���,����ת����ArrayList��ǿת�ᱨClassCastException
        ArrayList arrayList = (ArrayList) subList;

        //3�� array�޸ĺ�,subList�������½�ȡ,�����subList���κβ������ᱨjava.util.ConcurrentModificationException
        array.add(6);
        subList.get(0);
    }

    /**
     * ʹ�ü���ת����ķ��������봫���������ͺʹ�С
     */
    public static void b(){
        // 1��toArray()�޲η��������⣬ת�������Object[],ǿת����Ҫ�����ͻᱨClassCastException
        Integer[] objects = (Integer[]) array.toArray();

        // 2��ʹ��toArray()�вη���,����Ҫ�����������ͣ�����������С��ú�arrayһ�£����С����toArray()�ڲ������·����ַ
        Integer[] integers = new Integer[array.size()+1];
        int temp = integers.hashCode();
        integers = array.toArray(integers);
        System.out.println(integers.hashCode()==temp);
        // ���������������������λ�ö��ᱻ��Ϊnull ,һ�����ΪĬ����0,���ע����
        System.out.println(integers[array.size()]);
    }

    /**
     * ʹ��Arrays����������ת���ɼ���ʱ��һЩע���
     */
    public static void c(){
        Integer[] integers = {1,2,3,4,5};
        List list = Arrays.asList(integers);
        // 1��asList()���ص���Arrays���ڲ���,����ڲ���ֻ֧�ֶ�ȡ,����ֻ��add()�ᱨUnsupportedOperationException
        list.add(6);

        // 2����������ڲ����൱��һ���ӿ�,��������������̨�����ݻ�������
        integers[4] = 9;
        System.out.println(list.get(4));

    }


    public static void main(String[] args) {
        c();

    }

}
