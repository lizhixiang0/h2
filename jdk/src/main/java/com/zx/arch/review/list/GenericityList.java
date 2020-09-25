package com.zx.arch.review.list;

import java.util.List;

/**
 * @author lizx
 * @date 2020/09/22
 * @description 泛型通配符使用详解
 * @note "https://www.cnblogs.com/wxw7blog/p/7517343.html"
 **/
public class GenericityList {

    /**
     * 目的是为了可以传入list<任意类型>
     * 无界通配符
     * @param list
     */
    public static void a(List<?> list) {
        // 不允许使用add()方法,除了add(null)
        // 因为不能确定该List的类型, add什么类型都不行, 而null什么类型都不是。
        list.add(null);
        // 只能使用Object类类作为get方法的接收类
        // 因为Object是所有数据类型的父类
        Object o = list.get(2);
    }

    /**
     * 目的是为了限制，只能传入list<某类及其子类>
     * 固定上边界通配符
     * @param list
     */
    public static void b(List<? extends Number> list){
        // 不允许使用add()方法,除了add(null)
        // 例如里面如果写的是add(1.1) ,这时候传入list<Integer>就会出问题 （Integer和Long都是Number的子类）
        list.add(null);
        // 可以用Object类和Number类(上界)作为get方法的接收类
        Number string = list.get(0);
        Object o = list.get(2);
    }

    /**
     * 目的是为了限制，只能传入list<某类及其父类>
     * 固定下界通配符
     */
    public static void c(List<? super Integer> list){
        // 允许使用add方法！因为传入的必定是Integer或者其父类！我们add一个数字,比如1,它既是Integer类型 也是其父类类型！（多态）
        list.add(1);

        //只能使用Object类作为get方法的接收类
        Object o = list.get(1);
    }

    public static void main(String[] args) {

        /*
        * 总结:
                如果一个方法内部只需要对集合里的内容进行读取,那就使用extend！
                如果一个方法只需要对集合进行写操作！那就使用super！
                如果需要能读能写，不要使用通配符!
        * */
    }


}
