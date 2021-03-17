package com.zx.arch.proxy.cglib;

import net.sf.cglib.proxy.MethodInterceptor;
import net.sf.cglib.proxy.MethodProxy;

import java.lang.reflect.Method;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class AgentRole implements MethodInterceptor {

    Object result = null;

    @Override
    public Object intercept(Object o, Method method, Object[] objects, MethodProxy methodProxy) throws Throwable {
        // 打印对象的父类信息 ----> com.zx.arch.proxy.cglib.TrueRole
        System.out.println(o.getClass().getSuperclass().getName());
        // 代理
        System.out.println("before");
        result = methodProxy.invokeSuper(o, objects);
        System.out.println("after");
        return result;
    }
}
