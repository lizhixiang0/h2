package com.zx.arch.review.list;

import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 使用ArrayList有一些注意点
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
     *  在平时，需要取出集合中一部分数据时。通常会使用subList,它是array的内部类，也可以看做array的映射（视图）
     */
    public static void a(){
        List subList = array.subList(0,2);
        /*System.out.println(subList.size());
        //1、 subList删除一个元素,array也少了一个元素,所以说sublist是array的一个视图
        subList.remove(1);
        System.out.println(array.size());

        //2、subList作为array的内部类,不能转化成ArrayList，强转会报ClassCastException
        ArrayList arrayList = (ArrayList) subList;

        //3、 array修改后,subList必须重新截取,否则对subList的任何操作都会报java.util.ConcurrentModificationException
        array.add(6);
        subList.get(0);*/
    }

    /**
     * 使用集合转数组的方法，必须传入数组类型和大小
     */
    public static void b(){
        // 1、toArray()无参方法有问题，转化后的是Object[],强转成需要的类型会报ClassCastException
        Integer[] objects = (Integer[]) array.toArray();

        // 2、使用toArray()的重载有参方法,传入数组类型，另外注意传入的数组大小最好和array一致，如果小于则toArray()内部会重新分配地址
        // 我在看mybatis源码的时候，了解到有一种说法是推荐产地空数组！这样反而比较好！！
        Integer[] integers = new Integer[array.size()+1];
        int temp = integers.hashCode();
        integers = array.toArray(integers);
        System.out.println(integers.hashCode()==temp);
        // 如果大于则数组里多出来的位置都会被置为null ,一般会以为默认是0,这个注意下
        System.out.println(integers[array.size()]);
    }

    /**
     * 使用Arrays方法将数组转化成集合时有一些注意点
     */
    public static void c(){
        int[] ints = {1,2,3,4,5};
        // 1、基本类型不能作为 Arrays.asList方法的参数，否则会被当做一个参数
        // T是个继承于Object的类，并非基本类型，所以int[]作为参数导入时，T 为int[]。也就是Arrays.asList(传入一个int[]) 返回的是ArrayList<int[]>类型
        List list = Arrays.asList(ints);
        System.out.println(list.size());

        Integer[] integers = {1,2,3,4,5};
        list = Arrays.asList(integers);
        // 2、asList()返回的是Arrays的内部类,这个内部类只支持读取,所以只需add()会报UnsupportedOperationException
        // list.add(6);

        // 3、另外这个内部类相当于一个接口,类似适配器，后台的数据还是数组
        integers[4] = 9;
        System.out.println(list.get(4));
        System.out.println(list.size());

    }


    public static void main(String[] args) {
        c();
    }

}
