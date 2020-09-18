package com.zx.arch.unicode;
import java.io.*;

/**
 * @author lizx
 * @since 1.0.0
 * @description 彻底弄懂常见的7种中文字符编码  https://zhuanlan.zhihu.com/p/46216008
 **/
public class Blog {
    private  static  String path = Blog.class.getResource("/static/test.txt").getPath();

    // 字符编码要做的两件事:
    // 1、给所有的汉字（包括其他国家字符）一个独一无二的数字编号，做一个数字编号到汉字的mapping关系（即字符集）
    // 2、把这个数字编号能用0和1表示出来

    // Unicode 是什么？只是一个符号集!
    // Unicode，其实只做了第1件事情，并且是给全世界所有语言的所有文字或字母一个独一无二的数字编码

    // UTF-8是什么？它做的是第二件事！是存储unicode的实现方式!
    // UTF8解决字符间分隔的方式是数二进制中最高位连续1的个数来决定这个字是几字节编码。
    // 比如00000000 是单字节 ，和ASCII码重合，做到了兼容。
    // 比如11000000 10000000 是双字节
    // 汉字一般用UTF-8 表示需要3个字节
    // 最多6个字节。另外注意凡是不属于文字首字节的byte都以“10”开头

    // GBK 是什么？他既是一个字符集，同时也定义了存储方式!既所有符号都用两个字节表示！

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
     * 验证 GBK 和 ASCII 的关系   文件里是一个字——————> 阴0
     */
    private static void c() throws IOException {
        FileInputStream fileInputStream = new FileInputStream(path);
        int temp ;
        // 这里复习一波,字节流每次读一个字节byte,即8个bit位
        while((temp = fileInputStream.read())!=-1){
            System.out.println(Integer.toBinaryString(temp));
        }
        // 可以看到为三个字节 11010010 11110101 110000
        // 前两个代表汉字 ,后一个00110000 是ASCII一样，代表0  （UTF-8 中0也是00110000）
        // 那么这个格式是如何确定？第一个字节大于127(即第一个bit为1 )，就判断为汉字，读两个字节
        // 二进制转化成16进制  D2F5   http://tools.jb51.net/table/gbk_table
        String test1=Integer.toHexString(Integer.parseInt("1101001011110101",2)).toUpperCase();
        System.out.println(test1);
    }

    public static void main(String[] args) throws IOException {
        a("utf-8");
        c();
        // 补充: https://blog.csdn.net/longwen_zhi/article/details/79704687
    }

}
