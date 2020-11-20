package com.zx.arch.jdk;

import java.util.EmptyStackException;

/**
 * @author lizx
 * @since 1.0.0
 * @description  使用正则的一些注意点，以前使用正则时都是直接到网上去复制，但是有的用sonar扫描通不过。，特此记录
 * @blog "https://blog.csdn.net/hui820258300/article/details/103778885
 **/
public class RegexTest {

    /**
     * 下面这个去检查就很慢
     */
    private static void a(){
        String regex = "^(a+)+$";
        String a = "";
        System.out.println(a.matches(regex));
    }

    /**
     * 验证邮箱
     */
    public static void b() {
        /**
         * 这里的+都代表一个或者多个 ，没有加的意思。
         */
        String email="[A-Za-z0-9\\u4e00-\\u9fa5]+@[a-zA-Z0-9_-]+\\.+[a-zA-Z0-9_-]+";
        String a= "a@11.com";
        System.out.println(a.matches(email));
    }

    public static void main(String[] args) {
        a();
    }
}
