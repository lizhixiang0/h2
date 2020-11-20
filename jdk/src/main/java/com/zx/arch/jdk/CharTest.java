package com.zx.arch.jdk;

/**
 * @author lizx
 * @since 1.0.0
 * @description char类型到底是个啥,它和两个字节的unicode一一对应  （和四个字节的unicode没有关系）
 **/
public class CharTest {
    private static void a(){
        System.out.println("40869代表的汉字是:"+"\u9fa5"+"\r\n"+"19968代表的汉字是:"+"\u4e00");

        System.out.println((int)Character.MIN_VALUE);
        System.out.println((int)Character.MAX_VALUE);

    }

    public static void main(String[] args) {
        a();
    }
}
