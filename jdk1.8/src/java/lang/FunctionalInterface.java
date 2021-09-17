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
 * ��Ϣ��ע������, ����ָʾ�ӿ�����Java���Թ淶����Ĺ��ܽӿ�
 *
 * Conceptually, a functional interface has exactly one abstract method.  �Ӹ����Ͻ������ܽӿ���ȷֻ����һ�����󷽷�,���ھ�̬������Ĭ�Ϸ�������Ҫ��
 * Since default methods have an implementation, they are not abstract.  Ĭ�Ϸ��������ǳ��󷽷�, �ж��Ƿ���Ĭ�Ϸ�����{@linkplain java.lang.reflect.Method#isDefault()}
 * If an interface declares an abstract method overriding one of the public methods of {@code java.lang.Object}, that also does not count toward the interface's abstract method count since any implementation of the interface will have an implementation from java.lang.Object or elsewhere.
 * �з�����϶����ǳ��󷽷�,������������ڽӿ�Ĭ�ϼ̳�java.lang.Object,��������ӿ�������һ�����󷽷�������Object�еķ�������ôҲ���������󷽷���
 *
 * Note that instances of functional interfaces can be created with lambda expressions, method references, or constructor references. ע�⣬�����ӿڵ�ʵ��������lambda���ʽ���������û��캯�����ô�����
 *
 * If a type is annotated with this annotation type, compilers are required to generate an error message unless:
 *  1�� The type is an interface type and not an annotation type, enum, or class.
 *  2�� The annotated type satisfies the requirements of a functional interface.
 *
 * However, the compiler will treat any interface meeting the definition of a functional interface as a functional interface regardless of whether or not a FunctionalInterface annotation is present on the interface declaration.
 * Ȼ���������������κη��Ϻ����ӿڶ���Ľӿ���Ϊ�����ӿڣ������ܽӿ��������Ƿ����FunctionalInterfaceע��
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
