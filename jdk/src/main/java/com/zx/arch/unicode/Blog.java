package com.zx.arch.unicode;
import java.io.*;

/**
 * @author lizx
 * @since 1.0.0
 * @description ����Ū��������7�������ַ�����  https://zhuanlan.zhihu.com/p/46216008
 **/
public class Blog {
    private  static  String path = Blog.class.getResource("/static/test.txt").getPath();

    // �ַ�����Ҫ����������:
    // 1�������еĺ��֣��������������ַ���һ����һ�޶������ֱ�ţ���һ�����ֱ�ŵ����ֵ�mapping��ϵ�����ַ�����
    // 2����������ֱ������0��1��ʾ����

    // Unicode ��ʲô��ֻ��һ�����ż�!
    // Unicode����ʵֻ���˵�1�����飬�����Ǹ�ȫ�����������Ե��������ֻ���ĸһ����һ�޶������ֱ���

    // UTF-8��ʲô���������ǵڶ����£��Ǵ洢unicode��ʵ�ַ�ʽ!
    // UTF8����ַ���ָ��ķ�ʽ���������������λ����1�ĸ���������������Ǽ��ֽڱ��롣
    // ����00000000 �ǵ��ֽ� ����ASCII���غϣ������˼��ݡ�
    // ����11000000 10000000 ��˫�ֽ�
    // ����һ����UTF-8 ��ʾ��Ҫ3���ֽ�
    // ���6���ֽڡ�����ע�ⷲ�ǲ������������ֽڵ�byte���ԡ�10����ͷ

    // GBK ��ʲô��������һ���ַ�����ͬʱҲ�����˴洢��ʽ!�����з��Ŷ��������ֽڱ�ʾ��

    /**
     * ʹ��ָ����������ȡ�ļ�
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
     * ��֤unicode �� utf-8 �Ĺ�ϵ  �ļ�����һ���֡�����������> ��
     */
    private static void b() throws IOException {
        FileInputStream fileInputStream = new FileInputStream(path);
        int temp ;
        // ���︴ϰһ��,�ֽ���ÿ�ζ�һ���ֽ�byte,��8��bitλ
        while((temp = fileInputStream.read())!=-1){
            System.out.println(Integer.toBinaryString(temp));
        }
        // ���Կ���һ�����ֶ����������ֽڣ�11101001 10011000 10110100
        // ���������ж�����һ��utf-8�����ʽ  ������unicode������10010110 00110100
        // 2����ת����16���� Ϊ 9634  ,��unicode���ֱ�����ϲ�ѯ https://www.unicode.org/charts/unihan.html
        String test1=Integer.toHexString(Integer.parseInt("1001011000110100",2)).toUpperCase();

        // 16���ƻ���2����
        String test2 = Integer.toBinaryString(Integer.parseInt("9634", 16));
        System.out.println(test2);
    }

    /**
     * �ҵĵ�������±�Ĭ����UTF-8 �ı����ʽ������ִ���������֮ǰ�Ȱ��ļ������ʽ����GBK ,�����Ϊ����
     * ��֤ GBK �� ASCII �Ĺ�ϵ   �ļ�����һ���֡�����������> ��0
     */
    private static void c() throws IOException {
        FileInputStream fileInputStream = new FileInputStream(path);
        int temp ;
        // ���︴ϰһ��,�ֽ���ÿ�ζ�һ���ֽ�byte,��8��bitλ
        while((temp = fileInputStream.read())!=-1){
            System.out.println(Integer.toBinaryString(temp));
        }
        // ���Կ���Ϊ�����ֽ� 11010010 11110101 110000
        // ǰ���������� ,��һ��00110000 ��ASCIIһ��������0  ��UTF-8 ��0Ҳ��00110000��
        // ��ô�����ʽ�����ȷ������һ���ֽڴ���127(����һ��bitΪ1 )�����ж�Ϊ���֣��������ֽ�
        // ������ת����16����  D2F5   http://tools.jb51.net/table/gbk_table
        String test1=Integer.toHexString(Integer.parseInt("1101001011110101",2)).toUpperCase();
        System.out.println(test1);
    }

    public static void main(String[] args) throws IOException {
        a("utf-8");
        c();
        // ����: https://blog.csdn.net/longwen_zhi/article/details/79704687
    }

}
