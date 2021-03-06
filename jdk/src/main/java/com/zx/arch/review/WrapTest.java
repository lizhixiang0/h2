package com.zx.arch.review;

/**
 * @author lizx
 * @date 2020/07/26
 * @description 测试包装类
 *              1、比较大小不允许使用==,因为==比较的是地址！128以内地址相等，超过则内存地址不相等
 *              2、远程调用方法的返回值必须是包装类
 **/
public class WrapTest {
    public static void main(String[] args) {
        Integer a = 128;
        Integer b = 128;
        System.out.println(a.equals(b));
    }
    public Integer test(){
        // 逻辑处理,数据库操作可能返回一个null 出来 ,如果返回值是null，调用方做了判断还可以接受
        // 如果返回值是基本数据类型，返回nuLl 都通不过编译！！
        return null;
    }
}
