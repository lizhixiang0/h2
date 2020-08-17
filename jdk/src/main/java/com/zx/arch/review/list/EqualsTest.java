package com.zx.arch.review.list;

import java.util.HashMap;

/**
 * @author lizx
 * @date 2020/08/13
 * @description  理解 "=="、"equals"、"hashcode" 之间的区别和实际生产时的运用
 **/
public class EqualsTest {
    /**
     * 1、"==" 如果是基本类型，那比较的是值；引用类型则比较的是内存地址（即 内存地址必须相等）
     *
     * 2、equals 在objectl中调用了 "==",所以他比较的也是内存地址
     *   但是，string和基本类型包装类对这个进行了改写，变成了比较值。(即如果内存地址不相等，值相等也行)
     *
     * 3、hashcode 并不进行什么比较，而是可以借他调用本地方法得出内存地址的散列值，不同的类可能会得到相同的散列值
     */

    /**
     * 1、除非是基本类型，不然不要使用== ，因为很多时候我们判断类相等的标准是值相等
     * 2、网上很多说改写equals和hashcode的话题，根本原因是为了用于适应集合！
     *     因为通常我们不需要判断两个自定义对象是否相等！
     *
     *
     *     这里分主要是为了适应HashMap和Set集合

     *    对于hashmap,要求它的key值不能重复，他是先判断key的hashcode，如果hashcode相等再去比较equals！
     *    所以实际情况下，我们自定义一个类去作为hashmap的key,我们判断重复的标准是值相等！所以我们必定会去改写equals
     *    此时，如果不改写hashcode，那么就算值相等的两个自定义对象，也会被hashmap认定为不相等，因为它先判断的是hashcode!
     *    这里可以再说明一下，为什么hashmap会选择先判断hashcode,是为了提高效率。
     *    所以得出结论，使用hashmap时如果我们用自定义对象作为key,必须改写equals方法，和hashcode。
     *
     *    对于set集合，set集合判断两个对象是否相等的依据是比较 hashcode和equals
     *    同样的，他也是先比较hashcode ,如果hashcode不相等，就直接判断两个自定义对象不相等！
     *    如果我们new两个值一样的自定义对象，会都被存储到set集合中去。
     *    而我们使用set集合的初衷是存储值不一样的对象！！
     *    所以首先必须改写hashcode方法让他判断值，值不相等时会去看equals方法，此时比较的是内存地址，
     *    所以得出结论，如果使用set集合，必须改写hashcode方法。
     */


}
