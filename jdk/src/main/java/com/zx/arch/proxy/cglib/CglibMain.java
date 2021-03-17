package com.zx.arch.proxy.cglib;

import net.sf.cglib.proxy.Enhancer;

/**
 * CGLIB实现动态代理不需要接口
 * @author lizx
 * @since 1.0.0
 **/
public class CglibMain {
    public static void main(String[] args) {
        // 创建强化类
        Enhancer enhancer = new Enhancer();
        // 设置父类,并不需要是接口
        enhancer.setSuperclass(TrueRole.class);
        // 设置代理角色
        enhancer.setCallback(new AgentRole());
        // 创建代理类
        TrueRole tank = (TrueRole)enhancer.create();
        tank.move();
    }
}
