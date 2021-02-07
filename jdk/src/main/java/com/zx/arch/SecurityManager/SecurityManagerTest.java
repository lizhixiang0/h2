package com.zx.arch.SecurityManager;

import java.lang.reflect.Constructor;
import java.lang.reflect.ReflectPermission;

/**
 * @author lizx
 * @since 1.0.0
 * @description java安全管理器SecurityManager入门
 * @blog "https://www.cnblogs.com/yiwangzhibujian/p/6207212.html
 * @note 当我读mybatis源码反射模块是突然看到这方面的内容，借此了解下这是个啥 "https://blog.csdn.net/u010617952/article/details/109130535
 *
 **/
public class SecurityManagerTest {

    //默认构造函数
    private Constructor<?> defaultConstructor;

    private void addDefaultConstructor(Class<?> clazz) {
        Constructor<?>[] consts = clazz.getDeclaredConstructors();
        //循环，查询符合条件的构造函数
        for (Constructor<?> constructor : consts) {
            if (constructor.getParameterTypes().length == 0) {
                if (canAccessPrivateMethods()) {
                    try {
                        // 可以看到是在执行setAccessible之前调用了canAccessPrivateMethods方法。
                        constructor.setAccessible(true);
                    } catch (Exception e) {
                        // Ignored. This is only a final precaution, nothing we can do.
                    }
                }
                if (constructor.isAccessible()) {
                    this.defaultConstructor = constructor;
                }
            }
        }
    }

    /**
     * 查看安全管理器是否屏蔽了java对字段和方法的各种访问权限校验,默认是屏蔽的。
     */
    private static boolean canAccessPrivateMethods() {
        try {
            SecurityManager securityManager = System.getSecurityManager();
            if (null != securityManager) {
                securityManager.checkPermission(new ReflectPermission("suppressAccessChecks"));
            }
        } catch (SecurityException e) {
            return false;
        }
        return true;
    }

    public static void main(String[] args) {
        System.out.println(canAccessPrivateMethods());
    }
}
