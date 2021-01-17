package com.zx.arch.jdk;

import java.util.Arrays;

/**
 * @author lizx
 * @since 1.0.0
 * @description Escape sequence（转义字符简单理解）
 **/
public class EscTest {
    /**
     * 先看两个现象
     */

    /**
     * 现象一、
     */
    public static void a(){
        String str="a$b$c";
        String regex = "$";
        Arrays.stream(str.split(regex)).forEach(System.out::println);
    }

    /**
     * 现象二
     */
    public static void b(){
        System.out.println("\\");
    }

    public static void main(String[] args) {
        a(); //========  a$b$c
        b(); //========  \
        /**
         * 提出疑问,为什么$符号不能直接在split中使用？为什么要使用"\",前面需要再加一个"\"
         * 解答:  因为$和"\" 在java中都有特殊含义！譬如$在java中通常不代表美元,而是在正则表达式担当特殊的意义
         *        同时"\"在java中也不是表示反斜杠 ,而是表示转义字符
         *        所以如果用户就想使用$的字面含义"$",那必须的用"\"转义,同样如果用户需要的就是反斜杠"\"，同样要使用"\"转义！
         *        所以上面应该写成"\$"和"\\",java中还有很多字符有特殊含义！这些字符要使用其字面含义都得转义，
         *        补充：有些特殊的字符,转义后反而拥有特殊的作用，譬如\r\n
         *  拓展,如果需要将字符串中的反斜杠'\'替换成'',，如何实现？
         */

    }
}
