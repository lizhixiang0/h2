package com.zx.arch.jdk;

import java.util.EmptyStackException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author lizx
 * @since 1.0.0
 * @description  使用正则的一些注意点，以前使用正则时都是直接到网上去复制，但是有的用sonar扫描通不过。，特此记录
 * @blog "https://blog.csdn.net/hui820258300/article/details/103778885
 **/
public class RegexTest {

    // 正则应该这么用，预先编译好
    private static final Pattern PATTERN= Pattern.compile("[\u4E00-\u9FA5|\\！|\\，|\\。|\\（|\\）|\\《|\\》|\\“|\\”|\\？|\\：|\\；|\\【|\\】]");


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

    /**
     * 使用Pattern.compile预编译
     */
    public static void c(){
        Matcher m  = PATTERN.matcher("我是中文");
        System.out.println(m.find());
    }



    public static void main(String[] args) {
       c();
    }
}
