package com.zx.arch.designer.observer;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import java.util.HashMap;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @descripiton 观察者模式分析
 * @link "https://www.bilibili.com/video/BV1RC4y1H7ok?p=14
 * @note 在很多系统中,Observer模式往往和责任链共同负责对于事件的处理,其中的某一个observer负责是否将事件进一步传递
 **/
public class ObserverLeader {
    /**
     * 观察者模式进化链
     */
    static List develop = Lists.newArrayList();

    /**
     * study log
     */
    static void setBasicLogs() {
        develop.add("1、观察小孩哭,然后进行处理，面向过程");
        develop.add("2、稍微高级点了,使用面向对象，将小孩封装出来");
        develop.add("3、小孩（被观察者）内部加入dad(观察者)");
        develop.add("4、加入多个观察者");
        develop.add("5、使用多态,将观察者与被观察者解耦合\n");
        develop.add("6、有很多时候，观察者需要根据事件的具体情况来进行处理，将孩子的状态封装成事件对象");
        develop.add("7、大多数时候，我们处理事件的时候，需要事件源对象");
        develop.add("8、事件对象也可以形成继承体系");
    }
}
