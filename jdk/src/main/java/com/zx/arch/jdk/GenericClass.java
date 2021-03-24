package com.zx.arch.jdk;

import java.lang.reflect.Type;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class GenericClass {
    static class A<T>{}
    static class B<T> extends A<T>{}
    static class C extends B{
        public C(){}
    }

    public static void main(String[] args) {
        C c = new C();
        // C继承的B没有写明泛型，所以获得的父类不是泛型
        Type genericSuperclass = c.getClass().getGenericSuperclass();
        // C获得B的父类，是写明泛型的，所以拿到的是泛型，我只是说明的表象，深层的东西以后再了解
        Type genericSuperclass1 = c.getClass().getSuperclass().getGenericSuperclass();
        System.out.println(genericSuperclass instanceof Class);
        System.out.println(genericSuperclass.getTypeName());
        System.out.println(genericSuperclass1 instanceof Class);
        System.out.println(genericSuperclass1);

    }
}
