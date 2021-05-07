package com.zx.arch.designer;

import com.google.common.collect.Maps;
import com.zx.arch.designer.observer.ObserverLeader;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description  设计模式理解------马士兵的设计模式堪称全网最佳
 * @link "https://www.bilibili.com/video/BV1RC4y1H7ok
 **/
public class Leader {
    /**
     * 设计模式目录
     */
    static HashMap To_Analysis_Designer_logs = Maps.newHashMap();

    /**
     * study log
     */
    static void setBasicLogs() {
        // 二、核心分析
        To_Analysis_Designer_logs.put("观察者模式", ObserverLeader.class);
    }
}
