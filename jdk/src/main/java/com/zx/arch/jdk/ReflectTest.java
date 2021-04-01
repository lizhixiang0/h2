package com.zx.arch.jdk;

import java.lang.reflect.Method;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class ReflectTest {
    public static void main(String[] args) {
        // 获取所有方法,包括父类的方法,例如toString,此时getDeclaringClass(),是Object.class
        Method[] methods = ReflectTest.class.getMethods();
        // 获得子类声明的方法，子类声明的方法getDeclaringClass(),即使子类
        Method[] declaredMethods = ReflectTest.class.getDeclaredMethods();
        for (Method method:declaredMethods){
            System.out.println(method.getDeclaringClass());
            System.out.println(Object.class==method.getDeclaringClass());
        }
    }

    @Override
    public String toString() {
        return super.toString();
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
