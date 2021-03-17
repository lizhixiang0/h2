package com.zx.arch.proxy;

import com.google.common.collect.Maps;
import com.zx.arch.proxy.cglib.CglibMain;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description java的动态代理方式似乎有点多，所以这里做个记录
 * @blog "https://www.bilibili.com/video/BV1mD4y1d7rt?p=25
 * @blog "https://blog.csdn.net/lihenair/article/details/69948918
 * @blog "https://www.zhihu.com/question/40777626
 **/
public interface Leader {

    /**
     * 1、如何使用stream流
     */
    HashMap<String,Object> TO_USE_PROXY = Maps.newHashMap();

    /**
     * 2、分析流的原理
     */
    HashMap<String,Object> TO_ANALYSIS_PROXY = Maps.newHashMap();

    /**
     * study log
     */
    default void setBasicLogs() {
        TO_USE_PROXY.put("jdk动态代理是基于反射机制生成一个实现代理接口的匿名类","");
        TO_USE_PROXY.put("基于CGLib动态代理模式，原理是继承被代理类生成字代理类，不用实现接口，只需要被代理类是非final类即可。底层是asm字节码技术", CglibMain.class);
        TO_USE_PROXY.put("基于AspectJ实现动态代理。在程序编译的时候修改目标类的字节，织入代理的字节，不会生成全新的Class文件,但是spring只是借助aspect的注解,底层还是jdk和cglib","");
        TO_USE_PROXY.put("基于instrument实现动态代理。类加载的时候动态拦截去修改目标类的字节码,","");
        TO_USE_PROXY.put("asm是个动态代理框架,语法也是比较烦的,","");
        TO_USE_PROXY.put("javassist也是个动态代理框架,语法也是比较烦的,","");
    }
}
