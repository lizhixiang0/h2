/*
 * Copyright (c) 2012, 2013, Oracle and/or its affiliates. All rights reserved.
 * ORACLE PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */

package java.lang;

import java.lang.annotation.*;

/**
 * An informative annotation type used to indicate that an interface type declaration is intended to be a functional interface as defined by the Java Language Specification.
 * 信息性注释类型, 用于指示接口是由Java语言规范定义的功能接口
 *
 * Conceptually, a functional interface has exactly one abstract method.  从概念上讲，功能接口明确只能有一个抽象方法,至于静态方法和默认方法不做要求
 * Since default methods have an implementation, they are not abstract.  默认方法不算是抽象方法, 判断是否是默认方法：{@linkplain java.lang.reflect.Method#isDefault()}
 * If an interface declares an abstract method overriding one of the public methods of {@code java.lang.Object}, that also does not count toward the interface's abstract method count since any implementation of the interface will have an implementation from java.lang.Object or elsewhere.
 * 有方法体肯定不是抽象方法,有争议的是由于接口默认继承java.lang.Object,所以如果接口声明了一个抽象方法覆盖了Object中的方法，那么也不计作抽象方法。
 *
 * Note that instances of functional interfaces can be created with lambda expressions, method references, or constructor references. 注意，函数接口的实例可以用lambda表达式、方法引用或构造函数引用创建。
 *
 * If a type is annotated with this annotation type, compilers are required to generate an error message unless:
 *  1、 The type is an interface type and not an annotation type, enum, or class.
 *  2、 The annotated type satisfies the requirements of a functional interface.
 *
 * However, the compiler will treat any interface meeting the definition of a functional interface as a functional interface regardless of whether or not a FunctionalInterface annotation is present on the interface declaration.
 * 然而，编译器将把任何符合函数接口定义的接口视为函数接口，而不管接口声明中是否存在FunctionalInterface注释
 *
 * @jls 4.3.2. The Class Object
 * @jls 9.8 Functional Interfaces
 * @jls 9.4.3 Interface Method Body
 * @since 1.8
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface FunctionalInterface {}
