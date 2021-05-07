package com.zx.arch.designer.strategy;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 策略模式，comparator就是一种策略模式
 *     一个类定义了多种行为，并且这些行为在这个类的操作中以多个条件语句的形式出现，可将每个条件分支移入它们各自的策略类中以代替这些条件语句。
 * @link "https://www.bilibili.com/video/BV1RC4y1H7ok?p=3
 *              "http://c.biancheng.net/view/1378.html
 *
 *
 **/
public class StrategyLeader {
    /**
     * 策略模式进化链
     */
    static List develop = Lists.newArrayList();

    /**
     * study log
     */
    static void setBasicLogs() {
        develop.add("1、写一个排序器,对int数组进行排序");
        develop.add("2、对猫的体重进行排序");
        develop.add("3、对狗的体重进行排序");
        develop.add("4、如果想对猫的身高进行排序呢？");
        develop.add("5、测试:https://www.jianshu.com/p/3ea48ecd7178");
    }
}
