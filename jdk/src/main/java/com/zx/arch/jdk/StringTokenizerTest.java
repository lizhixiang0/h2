package com.zx.arch.jdk;

import java.util.StringTokenizer;

/**
 * @author lizx
 * @since 1.0.0
 * @description 认识StringTokenizer的用法,帮助程序员清理字符串中不想要的杂质
 *              默认会将字符串中的	"\t\r\r\f" 清除掉,也可以指定清除哪些杂质
 *
 **/
public class StringTokenizerTest {
    protected static  String removeBreakingWhitespace(String original) {
        // StringTokenizer 属于java.util包,用于分隔字符串
        StringTokenizer whitespaceStripper = new StringTokenizer(original,"d");
        StringBuilder builder = new StringBuilder();
        while (whitespaceStripper.hasMoreTokens()) {
            builder.append(whitespaceStripper.nextToken());
            builder.append(" ");
        }
        return builder.toString();
    }

    public static void main(String[] args) {
        String demo  = "ssssddsss ";
        System.out.println(demo);
        System.out.println(removeBreakingWhitespace(demo));
    }

}
