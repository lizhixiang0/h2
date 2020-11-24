package com.zx.arch.jdk;


/**
 * @author lizx
 * @date 2020/10/17
 * @ Java数值类型复习
 **/
public class UnSignedInt {

    /**
     * byte 去符号化
     */
    public static void a(){
        // Java中,byte在内存中占一个字节,取值范围为何是-128~127
        // 如果想用byte来表示0~256 ,用下面的方法！
        // 0~127 不变,
        // -128 变成 128
        // -127变成 129
        // 最后-1为 255
        byte a = -1;
        byte b = -127;
        int c = Byte.toUnsignedInt(a);
        int d = Byte.toUnsignedInt(b);
        System.out.println(c);
        System.out.println(d);
        System.out.println((byte)c);
        System.out.println((byte)d);

    }

    /**
     * 复习下16进制转10进制
     * 0xff 的10进制为255
     */
    public static void b(){
        // 0、1、2、3、4、5、6、7、8、9、A、B、C、D、E、F
        System.out.println("前面加0x代表16进制:"+0xff);
        System.out.println(15*16+15);

        // 2进制在java中如何表示
        System.out.println("前面加0b代表2进制:"+0b011);
    }

    /**
     * 研究 Byte.toUnsignedInt(a)底层原理
     *
     * "https://blog.csdn.net/leonwang_fly/article/details/47422235
     */
    public static void d() {
        byte a = -1;
        System.out.println(((int) a) & 0xff);
        System.out.println((int)a&225);
    }

    /**
     * java的多重转换   答案会是1吗？
     */
    public static void e(){
        System.out.println((int)(char)(byte)-1);
        //第一个问题,java中如何用二进制表示负数？
        //Java采用”2的补码“(Two's Complement)编码负数，它是一种数值的编码方法，
        // 要分二步完成：
        // 第一步，每一个二进制位都取相反值，0变成1，1变成0。比如，+8的二进制编码是00001000，取反后就是11110111。
        // 第二步，将上一步得到的值加1。11110111就变成11111000。所以，8的二进制补码就是11111000。
        // 即-8在计算机（8位机）中就是用11111000表示

        //第二个问题,什么是符号扩展？
        /*
        *符号扩展（Sign Extension）用于在数值类型转换时扩展二进制位的长度，以保证转换后的数值和原数值的符号（正或负）和大小相同，
        * 一般用于较窄的类型（如byte）向较宽的类型（如int）转换。
        * 扩展二进制位长度指的是，在原数值的二进制位左边补齐若干个符号位（0表示正，1表示负）。
        举例来说，用6个bit表示十进制数10，二进制码为"00 1010"，
        * 如果将它进行符号扩展为16bits长度，结果是"0000 0000 0000 1010"，
        * 即在左边补上10个0（因为10是正数，符号为0），符号扩展前后数值的大小和符号都保持不变；
        * 如果用10bits表示十进制数-15，使用“2的补码”编码后，二进制码为"11 1111 0001"，
        * 如果将它进行符号扩展为16bits，结果是"1111 1111 1111 0001",
        * 即在左边补上6个1（因为-15是负数，符号为1），符号扩展前后数值的大小和符号都保持不变。
*/


    }
    public static void main(String[] args) {
        d();
    }




}
