package com.zx.arch.designer.bridge;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description  桥接模式的核心即用组合关系代替继承关系，避免类爆炸问题
 *               将抽象的性质和具体的实现分离开，然后利用聚合，每次创建对象时先传入聚合对象
 *               前提是这个对象的基类不使用接口。（接口一般是定义动作,而非性质）
 * @link "http://c.biancheng.net/view/1364.html
 * @note 举例，定义不同颜色的不同水果，如果不使用桥接模式，需要多少个类。
 *             首先，颜色和水果种类属于属性，所以不能用接口,那么肯定是选择抽象类。
 *             接下来就是使用聚合。。。具体实现略过
 **/
public class BridgeLeader {
    /**
     * 桥接模式进化链
     */
    static List develop = Lists.newArrayList();

    /**
     * study log
     */
    static void setBasicLogs() {
        develop.add("");
    }
}
