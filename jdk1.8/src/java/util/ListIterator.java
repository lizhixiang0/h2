/*
 * Copyright (c) 1997, 2011, Oracle and/or its affiliates. All rights reserved.
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

/**
 * An iterator for lists that allows the programmer to traverse the list in either direction, modify the list during iteration, and obtain the iterator's current position in the list.
 * 用于列表的迭代器，允许程序员从任意方向遍历列表，在迭代期间修改列表，并获取迭代器在列表中的当前位置
 *
 * A ListIterator has no current element;  列表迭代器没有当前元素
 *
 * its cursor position always lies between the element that would be returned by a call to  previous() and the element that would be returned by a call to next().
 * 它的光标位置通常位于调用previous()返回的元素和调用next()返回的元素之间。
 *
 * An iterator for a list of length  n  has n+1 possible cursor positions, as illustrated by the carets ^ below:
 *
 * 对于长度为n的列表，迭代器有n+1个可能的游标位置，如下面的插入符号^所示:
 *                      Element(0)   Element(1)   Element(2)   ... Element(n-1)
 * cursor positions:  ^            ^            ^            ^                  ^
 *
 * Note that the remove and set(Object) methods are not defined in terms of the cursor position, they are defined to operate on the last element returned by a call to next or previous().
 * 注意，remove和set(Object)方法不是根据游标位置定义的,它们被定义为对调用next或previous()返回的最后一个元素进行操作。
 *
 * @since   1.2
 */
public interface ListIterator<E> extends Iterator<E> {
    // Query Operations

    /**
     * 如果这个列表迭代器在正向遍历列表时有更多的元素，则返回true
     * Returns true if this list iterator has more elements when traversing the list in the forward direction.
     * (In other words,returns true if next would return an element rather than throwing an exception.)
     */
    boolean hasNext();

    /**
     * 返回列表中的下一个元素并推进光标位置
     * Returns the next element in the list and advances the cursor position.
     * This method may be called repeatedly to iterate through the list,or intermixed with calls to previous to go back and forth.
     * (Note that alternating calls to next and  previous will return the same element repeatedly.)
     */
    E next();

    /**
     * 如果这个列表迭代器在反向遍历列表时有更多的元素，则返回true
     * Returns true if this list iterator has more elements when traversing the list in the reverse direction.
     * In other words,returns true if previous would return an element rather than throwing an exception.
     * 换句话说，如果previous返回一个元素而不是抛出一个异常，则返回true。
     */
    boolean hasPrevious();

    /**
     * 返回列表中的前一个元素并向后移动光标位置
     * Returns the previous element in the list and moves the cursor position backwards.
     * This method may be called repeatedly to iterate through the list backwards, or intermixed with calls to next to go back and forth.
     * 这个方法可以被反复调用以向后遍历列表，也可以与对next的调用混在一起来来回回
     * Note that alternating calls to next and previous will return the same element repeatedly.
     * 注意，交替调用next和previous将重复返回相同的元素。
     */
    E previous();

    /**
     * 返回将由后续调用next返回的元素的索引
     * Returns the index of the element that would be returned by a subsequent call to next.
     * Returns list size if the list iterator is at the end of the list.  如果列表迭代器位于列表的末尾，则返回列表大小
     */
    int nextIndex();

    /**
     * 返回元素的索引，该索引将由对previous的后续调用返回
     * Returns the index of the element that would be returned by a subsequent call to previous.
     * Returns -1 if the list iterator is at the beginning of the list.
     */
    int previousIndex();


    // Modification Operations

    /**
     * 从列表中移除next或previous返回的最后一个元素
     * Removes from the list the last element that was returned by next or previous (optional operation).
     * This call can only be made once per call to next or previous. 只有每次调用next或previous 才能调用此方法一次
     * It can be made only if add has not been called after the last call to next or previous. 只有在上次调用next或previous之后没有调用add时，才能进行此操作
     */
    void remove();

    /**
     * 将next或previous返回的最后一个元素替换为指定的元素
     * Replaces the last element returned by next or previous with the specified element (optional operation).
     * This call can be made only if neither remove nor add have been called after the last call to next or previous.
     * 只有在对next或previous的最后一次调用之后没有调用remove或add时，才能进行此调用
     *
     */
    void set(E e);

    /**
     * 将指定的元素插入列表(可选操作)
     * Inserts the specified element into the list (optional operation).
     *
     * The element is inserted immediately before the element that would be returned by next, if any, and after the element that would be returned by previous, if any.
     * 元素被插入到next返回的元素(如果有的话)的前面，以及previous返回的元素(如果有的话)的后面。
     *
     * If the list contains no elements, the new element becomes the sole element on the list.如果列表中不包含任何元素，则新元素将成为列表中唯一的元素
     * The new element is inserted before the implicit cursor: 在隐式游标之前插入新元素
     * a subsequent call to next would be unaffected, and a subsequent call to previous would return the new element. 对next的后续调用将不受影响，而对previous的后续调用将返回新元素
     * This call increases by one the value that would be returned by a call to nextIndex or previousIndex. 这个调用将调用nextIndex或previousIndex返回的值增加1。
     *
     */
    void add(E e);
}
