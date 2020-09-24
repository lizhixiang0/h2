package com.zx.arch.review;

/**
 * @author lizx
 * @date 2020/07/26
 * @Description  string 的split方法使用起来很麻烦，需要考虑很多东西
 * https://blog.csdn.net/qqxyy99/article/details/78861109
 **/
public class StringTest {
    public static void main(String[] args) {
        String string = ",a,b,c,,d,,";
        String[] strings = string.split(",",10);
        //如果不加-1 ,d前面的空字符能解析，但d后面的空字符串就解析不了，要保证比解析后的数组大即可
        // 如果把limit设置为非正，也能全部解析 .例如设置为 -1
        System.out.println(strings.length);
        //加上limit参数能保证解析后的数组长度肯定对的上，然后还得一个一个排查，是否为空字符串

    }
}
