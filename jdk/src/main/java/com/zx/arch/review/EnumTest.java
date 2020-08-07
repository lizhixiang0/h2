package com.zx.arch.review;

/**
 * @author lizx
 * @date 2020/07/26
 * @description 测试枚举类
 **/
public class EnumTest {
    public static void main(String[] args) {

    }
}

/*enum PurchaseOrderStatusEnum {

    UNCHECKED("UNCHECKED", "待审核"),
    LENDING("LENDING", "放款中"),
    UNRECEIVED("UNRECEIVED", "待收货"),
    FINISHED("FINISHED", "已完成"),
    INVALID("INVALID", "已作废");

    *//**
     * 构造方法，默认强制私有，所以不需要写修饰符号
     *//*
    PurchaseOrderStatusEnum(String storeCheck, String 囤货审核) {
        this.code = storeCheck;
        this.message = 囤货审核;
    }

    *//**
     * 通常将这个存入数据库
     *//*
    private String code;

    *//**
     * 枚举值的描述
     *//*
    private String message;


    *//**
     * 这个就是获取枚举值，事实上写成getCode()不影响啥。如果加了@Getter就咩必要写了
     *//*
    public String getValue() {
        return this.code;
    }
}*/
