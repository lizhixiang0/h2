package com.zx.arch.unicode;
import java.io.*;

/**
 * @author lizx
 * @since 1.0.0
 * @description ����Ū��������7�������ַ�����  https://zhuanlan.zhihu.com/p/46216008,ʵ����Ū�������ž�ɵ����
 **/
public class Blog {
    private  static  String path = Blog.class.getResource("/static/test.txt").getPath();

    // �ַ�����Ҫ����������:
    // 1�������еĺ��֣��������������ַ���һ����һ�޶������ֱ�ţ���һ�����ֱ�ŵ����ֵ�mapping��ϵ�����ַ�����
    // 2����������ֱ������0��1��ʾ����

    // Unicode ��ʲô��ֻ��һ�����ż�!
    // Unicode����ʵֻ���˵�1�����飬�����Ǹ�ȫ�����������Ե��������ֻ���ĸһ����һ�޶������ֱ���
    // ��չ:"http://blog.sina.com.cn/s/blog_4b4409c30100vw9t.html

    // UTF-8��ʲô���������ǵڶ����£��Ǵ洢unicode��ʵ�ַ�ʽ!
    // ����˵��һ��Ϊʲô����ֱ��ʹ��unicode,��Ϊ�����޷���ÿһ��unicode�ַ���ͬ�������ֽ�����ʾ������������UTF-8 ,��ʵ���Ǵ洢unicode��һ�ַ�ʽ���ѡ�
    // UTF8����ַ���ָ��ķ�ʽ���������������λ����1�ĸ���������������Ǽ��ֽڱ��롣
    // ע�ⷲ�ǲ������������ֽڵ�byte�����ǳ��˵�һ���ֽڵ������ֽڣ����ԡ�10����ͷ,��˼��ֻҪ10�����bit
    // ����00000000 �ǵ��ֽ� ����ASCII���غϣ������˼��ݡ�
    // ���� 11101001 10011000 10110100 �� ���ֽڣ�ȥ�����õ�bit,���õ�10010110 00110100
    // ����һ����UTF-8 ��ʾ��Ҫ3���ֽ�
    // ���6���ֽڡ����Ա�ʾ�ĸ��ֽڵ�unicode,���Ի���UTF-8���Ա�ʾ���Ե��ַ�!

    // GBK ��ʲô��������һ���ַ�����ͬʱҲ�����˴洢��ʽ!�����з��Ŷ��������ֽڱ�ʾ����ΪUTF-8��ʾ����̫�鷳�ˣ�̫ռ�ռ䣬���Բ�����GBK

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
        //�ļ�Ĭ����UTF-8 �ı����ʽ��������Ǽǵ��޸�
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
     * ��֤ GBK �� ASCII �Ĺ�ϵ   �ļ�����һ���֡�����������> ��
     * GBK����˫�ֽڱ�ʾ��������뷶ΧΪ8140-FEFE�����ֽ���81-FE ֮�䣬β�ֽ���40-FE ֮�䣬�޳� xx7Fһ���ߡ��ܼ�23940 ����λ
     */
    private static void c() throws IOException {
        FileInputStream fileInputStream = new FileInputStream(path);
        int temp ;
        // ���︴ϰһ��,�ֽ���ÿ�ζ�һ���ֽ�byte,��8��bitλ
        while((temp = fileInputStream.read())!=-1){
            System.out.println(Integer.toBinaryString(temp));
        }
        // ���Կ���Ϊ�����ֽ� 11010010 11110101  ,�ҵ�һ���ֽڴ���127(����һ��bitΪ1 )���ж�Ϊ���֣��������ֽ�
        // ������ת����16����  D2F5   http://tools.jb51.net/table/gbk_table
        String test1=Integer.toHexString(Integer.parseInt("1101001011110101",2)).toUpperCase();
        String test2=Integer.toString(Integer.parseInt("1101001011110101",2));
        System.out.println(test1);
        System.out.println(test2);
    }

    /**
     * ΪɶGBKת��UTF-8 ,��ת��GBK���ɻ�￼��
     * https://blog.csdn.net/u010234516/article/details/52853214
     */
    public static void d(){

    }
    public static void main(String[] args) throws IOException {
        //a("utf-8");
        c();
        // ����: https://blog.csdn.net/longwen_zhi/article/details/79704687
    }

}
