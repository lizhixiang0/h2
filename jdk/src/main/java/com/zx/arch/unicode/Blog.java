package com.zx.arch.unicode;
import java.io.*;

/**
 * @author lizx
 * @since 1.0.0
 * @description 彻底弄懂常见的7种中文字符编码  https://zhuanlan.zhihu.com/p/46216008,实际上弄不懂，信就傻逼了
 **/
public class Blog {
    private  static  String path = Blog.class.getResource("/static/test.txt").getPath();

    // 字符编码要做的两件事:
    // 1、给所有的汉字（包括其他国家字符）一个独一无二的数字编号，做一个数字编号到汉字的mapping关系（即字符集）
    // 2、把这个数字编号能用0和1表示出来

    // Unicode 是什么？只是一个符号集!
    // Unicode，其实只做了第1件事情，并且是给全世界所有语言的所有文字或字母一个独一无二的数字编码
    // 扩展:"http://blog.sina.com.cn/s/blog_4b4409c30100vw9t.html

    // UTF-8是什么？它做的是第二件事！是存储unicode的实现方式!
    // 这里说明一下为什么不能直接使用unicode,因为我们无法将每一个unicode字符用同数量的字节来表示。所以引入了UTF-8 ,其实就是存储unicode的一种方式而已。
    // UTF8解决字符间分隔的方式是数二进制中最高位连续1的个数来决定这个字是几字节编码。
    // 注意凡是不属于文字首字节的byte（就是除了第一个字节的其他字节）都以“10”开头,意思是只要10后面的bit
    // 比如00000000 是单字节 ，和ASCII码重合，做到了兼容。
    // 比如 11101001 10011000 10110100 是 三字节，去掉不用的bit,最后得到10010110 00110100
    // 汉字一般用UTF-8 表示需要3个字节
    // 最多6个字节。可以表示四个字节的unicode,所以基本UTF-8可以表示所以的字符!

    // GBK 是什么？他既是一个字符集，同时也定义了存储方式!既所有符号都用两个字节表示！因为UTF-8表示汉字太麻烦了，太占空间，所以采用了GBK

    /**
     * 使用指定编码来读取文件
     */
    private static void a(String charset) throws IOException {
        BufferedReader bufferedReader =
                new BufferedReader(new InputStreamReader(new FileInputStream(path), charset));
        String temp;
        if ((temp = bufferedReader.readLine()) != null) {
            System.out.println(temp);
        }
    }

    /**
     * 验证unicode 和 utf-8 的关系  文件里是一个字——————> 阴
     */
    private static void b() throws IOException {
        //文件默认是UTF-8 的编码格式，如果不是记得修改
        FileInputStream fileInputStream = new FileInputStream(path);
        int temp ;
        // 这里复习一波,字节流每次读一个字节byte,即8个bit位
        while((temp = fileInputStream.read())!=-1){
            System.out.println(Integer.toBinaryString(temp));
        }
        // 可以看到一个汉字读出了三个字节！11101001 10011000 10110100
        // 所以我们判断这是一个utf-8编码格式  那他的unicode编码是10010110 00110100
        // 2进制转化成16进制 为 9634  ,到unicode汉字编码表上查询 https://www.unicode.org/charts/unihan.html
        String test1=Integer.toHexString(Integer.parseInt("1001011000110100",2)).toUpperCase();

        // 16进制换成2进制
        String test2 = Integer.toBinaryString(Integer.parseInt("9634", 16));
        System.out.println(test2);
    }

    /**
     * 我的电脑里记事本默认是UTF-8 的编码格式，所以执行这个方法之前先把文件编码格式换成GBK ,点另存为即可
     * 验证 GBK 和 ASCII 的关系   文件里是一个字——————> 阴
     * GBK采用双字节表示，总体编码范围为8140-FEFE，首字节在81-FE 之间，尾字节在40-FE 之间，剔除 xx7F一条线。总计23940 个码位
     */
    private static void c() throws IOException {
        FileInputStream fileInputStream = new FileInputStream(path);
        int temp ;
        // 这里复习一波,字节流每次读一个字节byte,即8个bit位
        while((temp = fileInputStream.read())!=-1){
            System.out.println(Integer.toBinaryString(temp));
        }
        // 可以看到为两个字节 11010010 11110101  ,且第一个字节大于127(即第一个bit为1 )，判断为汉字，读两个字节
        // 二进制转化成16进制  D2F5   http://tools.jb51.net/table/gbk_table
        String test1=Integer.toHexString(Integer.parseInt("1101001011110101",2)).toUpperCase();
        String test2=Integer.toString(Integer.parseInt("1101001011110101",2));
        System.out.println(test1);
        System.out.println(test2);
    }

    /**
     * 为啥GBK转成UTF-8 ,再转成GBK会变成混斤考？
     * https://blog.csdn.net/u010234516/article/details/52853214
     */
    public static void d(){

    }
    public static void main(String[] args) throws IOException {
        //a("utf-8");
        c();
        // 补充: https://blog.csdn.net/longwen_zhi/article/details/79704687
    }

}
