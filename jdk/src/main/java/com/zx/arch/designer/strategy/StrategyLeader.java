package com.zx.arch.designer.strategy;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 策略模式
 * @link "https://www.bilibili.com/video/BV1RC4y1H7ok?p=3
 *              "http://c.biancheng.net/view/1378.html
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
        develop.add("1、观察小孩哭,然后进行处理，面向过程");
    }
}
