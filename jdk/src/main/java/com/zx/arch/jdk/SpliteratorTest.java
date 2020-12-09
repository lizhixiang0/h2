package com.zx.arch.jdk;

import java.util.ArrayList;
import java.util.List;
import java.util.Spliterator;

/**
 * @author lizx
 * @since 1.0.0
 * @description  认识可分割迭代Spliterator
 * @blog  "https://blog.csdn.net/weixin_44245828/article/details/109748173
 *
 **/
public class SpliteratorTest {

    private static List list = new ArrayList();
    static {
        list.add(1);
        list.add(2);
        list.add(3);
        list.add(4);
    }

    private static void a(){
        Spliterator spliterator = list.spliterator();
        spliterator.trySplit();
    }

    public static void main(String[] args) {
        a();
    }

}
