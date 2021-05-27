package com.zx.arch.designer.state;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 状态模式,如果一个类的方法是根据不同的状态有不同的实现，则使用state模式
 * @note        如果需要扩展行为(方法)，那不适合使用state模式
 * @link "https://www.bilibili.com/video/BV1RC4y1H7ok?p=52
 *       "http://c.biancheng.net/view/1388.html
 * @note 状态模式和策略模式的异同点：
 *      https://zhuanlan.zhihu.com/p/91912672
 **/
public class StateLeader {
    /**
     * 状态模式
     */
    static List develop = Lists.newArrayList();

    /**
     * study log
     */
    static void setBasicLogs() {
        develop.add("1、小女孩有两种状态,快乐和悲伤,不同的状态下,行为不同");
        develop.add("2、将状态抽象出来,需要增加新的状态时，直接增加一个状态类即可");
        develop.add("3、测试,模拟线程状态机来学习状态模式 https://blog.csdn.net/qq_44284002/article/details/104907326");
    }
}
