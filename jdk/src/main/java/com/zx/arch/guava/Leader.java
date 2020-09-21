package com.zx.arch.guava;

import com.google.common.collect.Maps;
import com.zx.arch.guava.BasicUtilities.ObjectsTest;
import com.zx.arch.guava.BasicUtilities.OptionalTest;
import com.zx.arch.guava.BasicUtilities.PreconditionsTest;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description Guava工程包含了若干被Google的 Java项目广泛依赖 的核心库
 **/
public interface Leader {
    /**
     * blog地址
     */
    String BLOG = "http://ifeve.com/google-guava/";
    /**
     * 1、基础工具包
     */
    HashMap Basic_Utilities_logs = Maps.newHashMap();

    /**
     * study log
     */
    default void setBasicLogs() {
        Basic_Utilities_logs.put("通过Optional来合理使用或者避免null", OptionalTest.class);
        Basic_Utilities_logs.put("Preconditions类中提供了若干前置条件判断的实用方法",PreconditionsTest.class);
        Basic_Utilities_logs.put("Guava改写了常见的Object方法",ObjectsTest.class);
    }


}
