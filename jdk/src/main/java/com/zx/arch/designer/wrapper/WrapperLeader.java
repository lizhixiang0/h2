package com.zx.arch.designer.wrapper;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description   包装器模式分为 1、适配器模式  2、装饰器模式
 *                一般使用包装器模式来避免大量的if else ,通常结合工厂模式
 * @note 两者的区别 "https://blog.csdn.net/hao65103940/article/details/91393939
 *       装饰器模式代码讲解：https://mp.weixin.qq.com/s/ZuWGli3d30TZO3RE2aQP9g
 *       感觉装饰器和代理模式有点像，区别是啥？像那个redis加全局锁，我觉得用装饰器模式也没毛病啊！
 *       这里讲了讲两者的区别：https://www.jianshu.com/p/c06a686dae39
 *       加redis锁还是适合用代理模式，因为这个行为不视为对原方法的增强！
 *
 *       可以这么理解：如果想要增强原方法，那就使用装饰器模式！
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
