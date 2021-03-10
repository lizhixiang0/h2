package com.zx.arch.collections;

import java.util.BitSet;

/**
 * @author lizx
 * @since 1.0.0
 * @description 虽然一字没用过BitSet,但是《java核心技术》提到了这个，再加上我查阅资料，说这个涉及位图,我对位图也不甚求解，所以记下来
 **/
public class BitSetTest {
    /**
     * 1、java中的位图是以Long作为数组元素，所以每个数组元素可以映射2^6个数字点位,网上讲解都是使用的int ，这点区别注意。
     * 2、取余运算和且运算的一点规律   1234%64 == 1234&(64-1)   取余的这个数必须是8的倍数   @blog https://www.iteblog.com/archives/148.html
     * 3、words[1234/64] |= (1L << 1234); 替换数组中的元素（数字对应点位变为1）
     *
     *    第一次插入1234,则words[1234/64] 处的元素二进制为 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
     *
     *    1L << 1234 == 1L << 1234%64 (18)的二进制为:    00000000 00000000 00000000 00000000 00000000 00000100 00000000 00000000  (目的是找到数字对应的点位在哪里，1234对应第19个元素的第46个点位)
     *
     *    两者进行或运算：00000000 00000000 00000000 00000000 00000000 00000100 00000000 00000000
     *
     *    可以看看words[19]是不是这个数：262144
     *
     */
    public static void a(){
        // 初始化的时候传入要映射的数组点位总数，比如下面我要映射128个数字,不传入默认64,然后每次set时会去判断一下，不够自己扩张一倍
        BitSet bitSet  = new BitSet(128);
        // 将127放入 bitSet中  ,-9223372036854775808
        bitSet.set(127);
        // 将128放入 bitSet中 , 因为上面只传入了128个点位,只能存放0~127 ，所以当传入128时，会扩张数组大小为原来的两倍
        bitSet.set(128);
        bitSet.set(1234);
        // 查看数字128存不存在对应的点位
        boolean bool = bitSet.get(128);
        System.out.println(bool);
    }

    /**
     * 位运算的小知识
     * @blog https://www.jianshu.com/p/927009730809
     * @note 如果进行位运算的是Long类型，那应该是取余64
     */
    public static void c(){
        System.out.println(1L << 1234);
        System.out.println(1L << 18);
        System.out.println(1234%64);
    }

    public static void main(String[] args) {
        a();
    }





}
