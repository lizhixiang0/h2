package com.zx.arch.stream;

import com.google.common.collect.Maps;
import com.zx.arch.stream.toAnalysis.StreamTest;
import com.zx.arch.stream.toUse.BaseStreamTest;
import com.zx.arch.stream.toUse.CreateStream;
import com.zx.arch.stream.toUse.ParallelStreamTest;
import com.zx.arch.stream.toUse.UpdateStream;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description 通过《java核心技术第十一版》学习stream流的用法
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
        // 一、简单入门
        To_Use_Stream_logs.put("生成stream的各类方法", CreateStream.class);
        To_Use_Stream_logs.put("操作stream的各类方法", UpdateStream.class);
        To_Use_Stream_logs.put("生成基本类型流", BaseStreamTest.class);
        To_Use_Stream_logs.put("并行流操作", ParallelStreamTest.class);

        // 二、核心分析
        To_Analysis_Stream_logs.put("提供者Supplier介绍", StreamTest.class);
    }


}
