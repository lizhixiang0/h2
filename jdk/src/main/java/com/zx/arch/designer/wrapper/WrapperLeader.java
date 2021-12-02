package com.zx.arch.designer.wrapper;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description   包装器模式分为 1、适配器模式  2、装饰器模式
 *                一般使用包装器模式来避免大量的if else ,通常结合工厂模式
 * @note 两者的区别 "https://blog.csdn.net/hao65103940/article/details/91393939
 *       代码讲解：https://mp.weixin.qq.com/s/ZuWGli3d30TZO3RE2aQP9g
 *
 **/
public class WrapperLeader {
    /**
     * 包装器模式进化链
     */
    static List develop = Lists.newArrayList();

    /**
     * study log
     */
    static void setBasicLogs() {
        develop.add("1、适配器模式");
        develop.add("2、装饰器模式");
    }
}
