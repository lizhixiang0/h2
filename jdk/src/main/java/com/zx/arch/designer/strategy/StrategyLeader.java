package com.zx.arch.designer.strategy;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 策略模式
 *              一个类需要好几种实现，则可以使用策略模式，比如支付，支付的形式有很多。比如存储系统,可以选择fastdfs或amazon
 *              spring中注入不同的bean的实现类即属于策略模式的最典型实现。
 *
 *              注：可以这样理解，以后项目中小到一个方法，大到一个功能！都用接口实现，当然前提是有多种实现方式，这个可以看是否有多个if else
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
        develop.add("5、spring经典实用:https://zhuanlan.zhihu.com/p/93860308");
        develop.add("6、网上写得比较ok的: https://blog.csdn.net/maxchenBug/article/details/101738795");
        develop.add("7、网上写得比较ok的: https://blog.csdn.net/maxchenBug/article/details/101738795");
    }
}
