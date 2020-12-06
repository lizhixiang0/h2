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

    /**
     * 很隐晦的语法错误，注释里也不许加转义序列
     * \1111
     * @param args
     */
    public static void main(String[] args) {
        // java中Double的isInfinite()和isNaN()
        //"https://www.cnblogs.com/xubiao/p/5461714.html
        a();
        //定义常量的规范,名字大写且加上final修饰符,当然通常常量前面会再加上static作为类常量
        final int CONST = 1;
        //int类型/0 会报语法错误，而浮点类型不会
        System.out.println(Double.isNaN(1.1f/0));
        //判断Unicode是否属于java的‘字母’，这里的字母指能66作为参数名
        System.out.println(Character.isJavaIdentifierPart('+'));
        System.out.println(Character.isJavaIdentifierPart('_'));


        // int 类型转换成float类型 ，精度会丢失
        // 解释为啥："https://blog.csdn.net/albertsh/article/details/92385277
        int n = 123456789;
        float f = n;
        System.out.println(f);
        System.out.println((int) f);
        System.out.println(Float.MAX_VALUE);

        int a = -100;
        System.out.println(a<<3); //   100*8
        System.out.println(a>>3); //   100/8
        System.out.println(a>>>3);
    }
}
