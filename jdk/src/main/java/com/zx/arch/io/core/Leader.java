package com.zx.arch.io.core;

import com.google.common.collect.Maps;
import com.zx.arch.io.core.toAnalysis.Demo01;
import com.zx.arch.stream.toAnalysis.StreamTest;
import com.zx.arch.stream.toUse.BaseStreamTest;
import com.zx.arch.stream.toUse.CreateStream;
import com.zx.arch.stream.toUse.ParallelStreamTest;
import com.zx.arch.stream.toUse.UpdateStream;
import com.zx.arch.threads.studyOne.Demo02;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description 通过《java核心技术第十一版》学习输入与输出
 **/
public interface Leader {

    /**
     * 1、如何使用IO
     */
    HashMap To_Use_IO_logs = Maps.newHashMap();

    /**
     * 2、分析IO的原理
     */
    HashMap To_Analysis_IO_logs = Maps.newHashMap();

    /**
     * study log
     */
    default void setBasicLogs() {
        // 一、简单入门

        // 二、核心分析
        To_Analysis_IO_logs.put("序列化和反序列化", Demo01.class);
    }
}
