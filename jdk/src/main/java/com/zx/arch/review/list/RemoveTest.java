package com.zx.arch.review.list;

import com.google.common.collect.Lists;

import java.util.ArrayList;

/**
 * @author lizx
 * @since 1.0.0
 * @description ������forѭ�������remove/add ����,�����Ҫ��ʹ��Iterator
 * @blog " https://www.cnblogs.com/liyong888/p/7799272.html
 **/
public class RemoveTest {
    private static ArrayList<String> list = Lists.newArrayList();

    static {
        list.add("a");
        list.add("b");
    }

    private static void a(){
        for (String string:list) {
            list.remove("b");
        }
        System.out.println(list.size());
    }

    public static void main(String[] args) {
        a();
    }


}
