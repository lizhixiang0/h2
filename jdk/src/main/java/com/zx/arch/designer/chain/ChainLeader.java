package com.zx.arch.designer.chain;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 责任链模式
 * @link spring中的filter "https://blog.csdn.net/lovejj1994/article/details/87457581
 * @vedio "https://www.bilibili.com/video/BV1RC4y1H7ok?p=40
 **/
public class ChainLeader {
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
