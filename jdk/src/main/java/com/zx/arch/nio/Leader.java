package com.zx.arch.nio;

import com.google.common.collect.Maps;
import com.zx.arch.guava.BasicUtilities.*;
import com.zx.arch.guava.collections.MultisetTest;
import com.zx.arch.guava.collections.UnmodifiableListTest;
import com.zx.arch.guava.collections.UtilsTest;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description Java NIO提供了与标准IO不同的IO工作方式,可以替代标准Java IO API的IO API
 * @blog  "https://www.cnblogs.com/XuYiHe/p/9111458.html
 **/
public interface Leader {
    /**
     * blog地址
     */
    String BLOG = "https://ifeve.com/java-nio-all/";

    /**
     * study log
     */
    default void setBasicLogs() {

    }


}
