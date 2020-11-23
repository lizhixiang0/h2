package com.zx.arch.jdk;

/**
 * @author lizx
 * @since 1.0.0
 * @description char类型到底是个啥,他是unicode 的一个代码单元！
 **/
public class CharTest {
    private static void a(){
        System.out.println("40869代表的汉字是:"+"\u9fa5"+"\r\n"+"19968代表的汉字是:"+"\u4e00");

        System.out.println((int)Character.MIN_VALUE);
        System.out.println((int)Character.MAX_VALUE);


    }

    public static void main(String[] args) {
        // java中Double的isInfinite()和isNaN()
        //"https://www.cnblogs.com/xubiao/p/5461714.html
        a();
    }
}
