package com.zx.arch.designer.chain;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 责任链模式,一个事件需要经过多个对象来流程化处理，譬如采购审批流程，请假流程，软件开发中的异常处理流程，web请求处理流程等各种各样的流程，可以考虑使用责任链模式来实现。
 *                 注：责任链强调事件层层传递，最后传递到能处理的人那里去！处理完返回！中间的每一环都可以做判断是否采取行为！也可以控制链条是否停止！
 *                     spring中的filter责任链就是这样的！并不是每个filter都会工作！而是根据条件！
 * @link spring中的filter "https://blog.csdn.net/lovejj1994/article/details/87457581
 * @vedio "https://www.bilibili.com/video/BV1RC4y1H7ok?p=40
 *        http://c.biancheng.net/view/1383.html
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
        develop.add("1、论坛发消息,后台需要经过信息处理才会允许存入数据库或者发表");
        develop.add("2、从不同的处理方式里抽象出一个Filter类,里面有一个doFilter方法，然后创建不同的实现类");
        develop.add("3、增加一个责任链类，用来集中处理filter ");
        develop.add("4、调用链也实现filter抽象类,即链条也是一个filter类");
        develop.add("5、链条中的filter需要有控制链条停止的能力");
        // 下面是拓展
        develop.add("6、之前都是处理一个message,现在要求换成两个,一个request,一个response");
        develop.add("7、控制处理request和response的顺序，先处理request,再处理response");
        develop.add("8、实例测试,https://blog.csdn.net/wwwdc1012/article/details/83592323");
    }
}
