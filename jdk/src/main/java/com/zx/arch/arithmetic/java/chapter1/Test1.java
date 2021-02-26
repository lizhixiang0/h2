package com.zx.arch.arithmetic.java.chapter1;

import java.util.ArrayList;
import java.util.HashSet;

/**
 * @author lizx
 * @since 1.0.0
 * @description "给一个字符串，比如ABC， 把所有的排列，即：ABC, ACB, BAC, BCA, CAB, CBC 都找出来。"
 *
 **/
public class Test1 {
    public static void main(String[] args) {
        Test1 a27 = new Test1();
        System.out.println(a27.exec("abcd"));
    }

    public ArrayList<String> exec(String str) {
        ArrayList<String> list = new ArrayList<>();
        if (str != null && str.length() != 0) {
            fun(str.toCharArray(), 0, list);
            // 最后再去重一次
            list  = new ArrayList<String>(new HashSet<>(list));
        }
        return list;
    }

    private void fun(char[] cs, int i, ArrayList<String> list) {
        if (i == cs.length - 1) {
            list.add(String.valueOf(cs));
        }else {
            for (int j = i; j < cs.length; j++) {
                // 交换索引i和j上的元素,第一次循环j与i相等，相当于第一个位置自身交换，之后j != i，则会真正交换两个不同位置上的字符
                swap(i, j, cs);
                // 交换完成之后，再递归处理交换得到的cls排列，i依次加1,直到i==cs.size()-1，进行输出
                fun(cs, i+1, list);
                // 复位,待第二次交换
                swap(i, j, cs);
            }
        }
    }


    private void swap(int i, int j, char[] cs) {
        char temp = cs[j];
        cs[j] = cs[i];
        cs[i] = temp;
    }

}
