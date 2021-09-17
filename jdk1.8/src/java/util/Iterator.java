/*
 * Copyright (c) 1997, 2013, Oracle and/or its affiliates. All rights reserved.
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

package java.util;

import java.util.function.Consumer;

/**
 * An iterator over a collection.  �Լ��Ͻ��е����ĵ�����
 * Iterator takes the place of Enumeration in the Java Collections Framework. ������ȡ����java���Ͽ�ܵ�ö����
 * Iterators differ from enumerations in two ways: ��������ö�������㲻ͬ
 *
 * 1��Iterators allow the caller to remove elements from the underlying collection during the iteration with well-defined semantics.  �������õ�����
 *      ����������������ڵ����ڼ�ӵ�������ָ���collection�Ƴ�Ԫ��
 * 2��Method names have been improved.
 *      �������Ƶõ��˸Ľ�

 * @blog "https://www.cnblogs.com/qlky/p/7367791.html
 * @since 1.2
 */
public interface Iterator<E> {
    /**
     * ���������������Ԫ���򷵻�true��
     * Returns true if the iteration has more elements.
     * In other words, returns true if next would return an element rather than throwing an exception.
     *
     * @return {@code true} if the iteration has more elements
     */
    boolean hasNext();

    /**
     * ���ص����е���һ��Ԫ�ء�
     * Returns the next element in the iteration.
     * @return the next element in the iteration
     * @throws NoSuchElementException if the iteration has no more elements
     */
    E next();

    /**
     * Removes from the underlying collection the last element returned by this iterator (optional operation).
     * �Ӽ������Ƴ��˵��������ص����һ��Ԫ��(��ѡ����)��
     *
     * This method can be called only once per call to next.
     * ֻ��ÿ�ε���next����ܵ��ô˷���һ��
     *
     * The behavior of an iterator is unspecified if the underlying collection is modified while the iteration is in progress in any way other than by calling this  method.
     * ����ڵ������й��������κη�ʽ�޸Ļ������϶����ǵ��ô˷���,�����������Ϊ�ǲ�ȷ����
     *
     * @implSpec
     * The default implementation throws an instance of UnsupportedOperationException and performs no other action.
     *
     * @throws UnsupportedOperationException if the remove operation is not supported by this iterator
     *
     * @throws IllegalStateException if the next method has not yet been called, or the remove method has already been called after the last call to the next method
     */
    default void remove() {
        throw new UnsupportedOperationException("remove");
    }

    /**
     * Performs the given action for each remaining element until all elements have been processed or the action throws an exception.
     * Actions are performed in the order of iteration, if that order is specified.
     * Exceptions thrown by the action are relayed to the caller.   �ɶ����������쳣��ת����������    be relayed to  ������
     *
     * @implSpec
     * <p>The default implementation behaves as if:
     * <pre>{@code
     *     while (hasNext())
     *         action.accept(next());
     * }</pre>
     *
     * @param action The action to be performed for each element
     * @throws NullPointerException if the specified action is null
     * @since 1.8
     */
    default void forEachRemaining(Consumer<? super E> action) {
        Objects.requireNonNull(action);
        while (hasNext())
            action.accept(next());
    }
}
