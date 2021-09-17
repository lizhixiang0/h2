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
 * An iterator over a collection.  对集合进行迭代的迭代器
 * Iterator takes the place of Enumeration in the Java Collections Framework. 迭代器取代了java集合框架的枚举类
 * Iterators differ from enumerations in two ways: 迭代器与枚举有两点不同
 *
 * 1、Iterators allow the caller to remove elements from the underlying collection during the iteration with well-defined semantics.  定义良好的语义
 *      迭代器允许调用者在迭代期间从迭代器所指向的collection移除元素
 * 2、Method names have been improved.
 *      方法名称得到了改进

 * @blog "https://www.cnblogs.com/qlky/p/7367791.html
 * @since 1.2
 */
public interface Iterator<E> {
    /**
     * 如果迭代包含更多元素则返回true。
     * Returns true if the iteration has more elements.
     * In other words, returns true if next would return an element rather than throwing an exception.
     *
     * @return {@code true} if the iteration has more elements
     */
    boolean hasNext();

    /**
     * 返回迭代中的下一个元素。
     * Returns the next element in the iteration.
     * @return the next element in the iteration
     * @throws NoSuchElementException if the iteration has no more elements
     */
    E next();

    /**
     * Removes from the underlying collection the last element returned by this iterator (optional operation).
     * 从集合中移除此迭代器返回的最后一个元素(可选操作)。
     *
     * This method can be called only once per call to next.
     * 只有每次调用next后才能调用此方法一次
     *
     * The behavior of an iterator is unspecified if the underlying collection is modified while the iteration is in progress in any way other than by calling this  method.
     * 如果在迭代进行过程中以任何方式修改基础集合而不是调用此方法,则迭代器的行为是不确定的
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
     * Exceptions thrown by the action are relayed to the caller.   由动作引发的异常被转发给调用者    be relayed to  被传给
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
