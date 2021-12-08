package com.zx.arch.jdk;

/**
 * @author lizx
 * @date 2021/12/8
 * @since
 * @blog
 * "https://www.cnblogs.com/dolphin0520/p/3736238.html
 * https://blog.csdn.net/a846029405/article/details/84651119
 * https://blog.csdn.net/qq_43498836/article/details/106579979
 *
 **/
public class FinalTest {
    /**
     * 方法中final变量和普通变量
     * @param args
     */
        public static void main(String[] args)  {
            String a = "hello2";

            final String b = "hello";  // 当final变量是基本数据类型以及String类型时，如果在编译期间能知道它的确切值，则编译器会把它当做编译期常量使用
            String c = b + 2;  //  字符串常量相加,编译器直接识别为hello2，从常量池中取出引用交给变量c


            String d = "hello";
            String e = d + 2;  //  字符串变量加上常量，会创建 StringBuilder 对象，然后append(d)

            // ==比较的是地址
            System.out.println(a == c); // true
            System.out.println(a == e); // false
    }
}
