package com.zx.arch.designer.builder;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 如果对象有多个属性,并且是可选属性（可选！！），则适合用建造者模式
 *              可选的属性用抽象方法来set，不可选的放到构造方法中
 *
 * @blog "https://zhuanlan.zhihu.com/p/58093669
 **/
public class BuilderLeader {
    /**
     * 建造者模式进化链
     */
    static List develop = Lists.newArrayList();

    /**
     * study log
     */
    static void setBasicLogs() {
        develop.add("");
    }
}
