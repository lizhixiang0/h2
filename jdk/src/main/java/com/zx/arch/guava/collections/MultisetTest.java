package com.zx.arch.guava.collections;

import com.google.common.collect.HashMultiset;
import com.google.common.collect.Multiset;
import org.springframework.core.NamedInheritableThreadLocal;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author lizx
 * @since 1.0.0
 * @blog "http://ifeve.com/google-guava-newcollectiontypes/
 *       "https://www.cnblogs.com/peida/p/Guava_Multiset.html
 * @description  Guava引进了JDK里没有的，但是非常有用的一些新的集合类型
 *
 *      Guava中定义的新集合有：
 * 　　                       Multiset
 * 　　                       SortedMultiset
 * 　　                       Multimap
 * 　　                       ListMultimap
 * 　　                       SetMultimap
 * 　　                       BiMap
 * 　　                       ClassToInstanceMap
 * 　　                       Table
 **/
public class MultisetTest {
    private static  String[] words = {"a","a","a","c","c"};

    /**
     * 统计一个词在文档中出现了多少次，传统的做法如下
     * 缺点：不支持同时收集多种统计信息，如总词数
     */
    public static void a(){
        Map<String, Integer> counts = new HashMap<>(16);
        for (String word : words) {
            Integer count = counts.get(word);
            if (count == null) {
                counts.put(word, 1);
            } else {
                counts.put(word, count + 1);
            }
        }
    }

    /**
     * Guava提供了一个新集合类型 Multiset
     * 特点: Multiset占据了List和Set之间的一个灰色地带：允许重复，但是不保证顺序。
     * 注意: Multiset继承自JDK中的Collection接口，而不是Set接口,不要被名字误导
     * 方法：
     *      add(E)添加单个给定元素
     *      iterator()返回一个迭代器，包含Multiset的所有元素（包括重复的元素）
     *      size()返回所有元素的总个数（包括重复的元素）
     *
     *      count(Object)返回给定元素的计数。
     *      entrySet()返回Set<Multiset.Entry<E>>，和Map的entrySet类似。
     *      elementSet()返回所有不重复元素的Set<E>，和Map的keySet()类似。
     *
     *      remove(E, int)	减少给定元素在Multiset中的计数
     *      setCount(E, int)	设置给定元素在Multiset中的计数，不可以为负数
     */
    public static void b(){
        Multiset<String> stringMultiset = HashMultiset.create();
        stringMultiset.addAll(Arrays.asList(words));
        System.out.println("返回words中元素的总个数:"+stringMultiset.size());
        System.out.println("返回元素a的总个数:"+stringMultiset.count("a"));
        System.out.println("返回所有元素(去重):"+stringMultiset.elementSet().toString());
    }

    public static void main(String[] args) {
        b();
    }
}
