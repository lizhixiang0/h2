package com.zx.arch.stream;

import com.google.common.collect.Maps;
import com.zx.arch.stream.toUse.Demo1;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description 用以系统的学习stream流的用法
 * @blog  "https://ifeve.com/stream/
 **/
public interface Leader {
    /**
     * blog地址
     */
    String BLOG = "https://ifeve.com/stream/";

    /**
     * 1、如何使用stream流
     */
    HashMap To_Use_Stream_logs = Maps.newHashMap();

    /**
     * 2、分析流的原理
     */
    HashMap To_Analysis_Stream_logs = Maps.newHashMap();

    /**
     * study log
     */
    default void setBasicLogs() {
        To_Use_Stream_logs.put("Stream入门", Demo1.class);
    }


}
