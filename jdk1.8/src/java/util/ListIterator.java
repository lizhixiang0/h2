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
 * �����б�ĵ��������������Ա�����ⷽ������б��ڵ����ڼ��޸��б�����ȡ���������б��еĵ�ǰλ��
 *
 * A ListIterator has no current element;  �б������û�е�ǰԪ��
 *
 * its cursor position always lies between the element that would be returned by a call to  previous() and the element that would be returned by a call to next().
 * ���Ĺ��λ��ͨ��λ�ڵ���previous()���ص�Ԫ�غ͵���next()���ص�Ԫ��֮�䡣
 *
 * An iterator for a list of length  n  has n+1 possible cursor positions, as illustrated by the carets ^ below:
 *
 * ���ڳ���Ϊn���б���������n+1�����ܵ��α�λ�ã�������Ĳ������^��ʾ:
 *                      Element(0)   Element(1)   Element(2)   ... Element(n-1)
 * cursor positions:  ^            ^            ^            ^                  ^
 *
 * Note that the remove and set(Object) methods are not defined in terms of the cursor position, they are defined to operate on the last element returned by a call to next or previous().
 * ע�⣬remove��set(Object)�������Ǹ����α�λ�ö����,���Ǳ�����Ϊ�Ե���next��previous()���ص����һ��Ԫ�ؽ��в�����
 *
 * @since   1.2
 */
public interface ListIterator<E> extends Iterator<E> {
    // Query Operations

    /**
     * �������б����������������б�ʱ�и����Ԫ�أ��򷵻�true
     * Returns true if this list iterator has more elements when traversing the list in the forward direction.
     * (In other words,returns true if next would return an element rather than throwing an exception.)
     */
    boolean hasNext();

    /**
     * �����б��е���һ��Ԫ�ز��ƽ����λ��
     * Returns the next element in the list and advances the cursor position.
     * This method may be called repeatedly to iterate through the list,or intermixed with calls to previous to go back and forth.
     * (Note that alternating calls to next and  previous will return the same element repeatedly.)
     */
    E next();

    /**
     * �������б�������ڷ�������б�ʱ�и����Ԫ�أ��򷵻�true
     * Returns true if this list iterator has more elements when traversing the list in the reverse direction.
     * In other words,returns true if previous would return an element rather than throwing an exception.
     * ���仰˵�����previous����һ��Ԫ�ض������׳�һ���쳣���򷵻�true��
     */
    boolean hasPrevious();

    /**
     * �����б��е�ǰһ��Ԫ�ز�����ƶ����λ��
     * Returns the previous element in the list and moves the cursor position backwards.
     * This method may be called repeatedly to iterate through the list backwards, or intermixed with calls to next to go back and forth.
     * ����������Ա������������������б�Ҳ�������next�ĵ��û���һ�������ػ�
     * Note that alternating calls to next and previous will return the same element repeatedly.
     * ע�⣬�������next��previous���ظ�������ͬ��Ԫ�ء�
     */
    E previous();

    /**
     * ���ؽ��ɺ�������next���ص�Ԫ�ص�����
     * Returns the index of the element that would be returned by a subsequent call to next.
     * Returns list size if the list iterator is at the end of the list.  ����б������λ���б��ĩβ���򷵻��б��С
     */
    int nextIndex();

    /**
     * ����Ԫ�ص����������������ɶ�previous�ĺ������÷���
     * Returns the index of the element that would be returned by a subsequent call to previous.
     * Returns -1 if the list iterator is at the beginning of the list.
     */
    int previousIndex();


    // Modification Operations

    /**
     * ���б����Ƴ�next��previous���ص����һ��Ԫ��
     * Removes from the list the last element that was returned by next or previous (optional operation).
     * This call can only be made once per call to next or previous. ֻ��ÿ�ε���next��previous ���ܵ��ô˷���һ��
     * It can be made only if add has not been called after the last call to next or previous. ֻ�����ϴε���next��previous֮��û�е���addʱ�����ܽ��д˲���
     */
    void remove();

    /**
     * ��next��previous���ص����һ��Ԫ���滻Ϊָ����Ԫ��
     * Replaces the last element returned by next or previous with the specified element (optional operation).
     * This call can be made only if neither remove nor add have been called after the last call to next or previous.
     * ֻ���ڶ�next��previous�����һ�ε���֮��û�е���remove��addʱ�����ܽ��д˵���
     *
     */
    void set(E e);

    /**
     * ��ָ����Ԫ�ز����б�(��ѡ����)
     * Inserts the specified element into the list (optional operation).
     *
     * The element is inserted immediately before the element that would be returned by next, if any, and after the element that would be returned by previous, if any.
     * Ԫ�ر����뵽next���ص�Ԫ��(����еĻ�)��ǰ�棬�Լ�previous���ص�Ԫ��(����еĻ�)�ĺ��档
     *
     * If the list contains no elements, the new element becomes the sole element on the list.����б��в������κ�Ԫ�أ�����Ԫ�ؽ���Ϊ�б���Ψһ��Ԫ��
     * The new element is inserted before the implicit cursor: ����ʽ�α�֮ǰ������Ԫ��
     * a subsequent call to next would be unaffected, and a subsequent call to previous would return the new element. ��next�ĺ������ý�����Ӱ�죬����previous�ĺ������ý�������Ԫ��
     * This call increases by one the value that would be returned by a call to nextIndex or previousIndex. ������ý�����nextIndex��previousIndex���ص�ֵ����1��
     *
     */
    void add(E e);
}
