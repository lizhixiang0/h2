package com.zx.arch.guava.BasicUtilities;

import static com.google.common.base.Preconditions.*;

/**
 * @author lizx
 * @description 参数检查是一个项目中必须要考虑到的。参数检查前端要做，后端更要做。这决定了一个项目的健壮性和安全性。
 *              guava的Preconditions类可以简单，优雅的帮助我们实现参数检查。
 * @since 1.0.0
 **/
public class PreconditionsTest {

    /**
     * 自己编写规则进行参数判断
     */
    private static void a(int a, int b) {
        // Exception in thread "main" java.lang.IllegalArgumentException: Expected a > b, but 2 > 1
        checkArgument(a > b, "Expected a > b, but %s > %s", b, a);
    }

    /**
     * 判断参数是否为null
     */
    private static void b(String a){
        // 检查value是否为null，该方法直接返回value ! 如果a是null 则直接报NPE
        a = checkNotNull(a);
    }

    /**
     * 判断对象状态
     */
    private static void c(boolean a){
        // 非true报IllegalStateException
        checkState(a);
    }

    /**
     * 检查index作为索引值对某个列表、字符串或数组是否有效。index>=0 && index<size  ，超出范围报IndexOutOfBoundsException
     * @param index  需要用到的索引
     * @param size   传入列表、字符串或数组的大小
     */
    private static void d(int index, int size){
        index = checkElementIndex(index,size);

        // 检查index作为位置值对某个列表、字符串或数组是否有效。index>=0 && index<=size *
        // 注意和这个绝对地址 支持index = size
        // 索引值常用来查找列表、字符串或数组中的元素 ,位置值和位置范围常用来截取列表、字符串或数组
        index = checkPositionIndex(index, size);
    }

    /**
     * 检查[start, end]表示的位置范围对某个列表、字符串或数组是否有效*
     * @param start
     * @param end
     * @param size  列表、字符串或数组的大小
     */
    private static void e(int start, int end, int size){
        checkPositionIndexes(start,end,size);
    }

    public static void main(String[] args) {
        // 实战 https://blog.csdn.net/qfycc92/article/details/44700869
        // 注意哪些是有返回值，这些可以无缝接入代码
    }
}
