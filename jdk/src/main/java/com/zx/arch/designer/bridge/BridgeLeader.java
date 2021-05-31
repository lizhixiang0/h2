package com.zx.arch.designer.bridge;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
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
        develop.add("1、论坛发消息,后台需要经过信息处理才会允许存入数据库或者发表");
    }
}
