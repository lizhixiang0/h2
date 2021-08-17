/*
 * Copyright (c) 2000, 2006, Oracle and/or its affiliates. All rights reserved.
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
 *  RandomAccess��һ���սӿڣ����սӿڵ�����һ������һ����ʶ�����á�
 * ͨ�׵㽲�������ж�һ��list�Ƿ�ʵ����RandomAccess�ӿڣ����ʵ���ˣ����ü򵥵�forѭ�����з����ٶȱȽϿ졣
 * ���δʵ��RandomAccess�ӿڣ������iteratorѭ�������ٶȱȽϿ졣
 *
 * Marker interface ��ǽӿ� used by <tt>List</tt> implementations to indicate that
 * they support fast (generally constant time) random access �����ȡ.  The primary
 * purpose of this interface is to allow generic algorithms �����㷨 to alter their
 * behavior to provide good performance when applied to either random or
 * sequential access lists Ӧ���������˳��洢�б�.
 *
 * Listʵ����ʹ�õı�ǽӿڣ���������ʵ������Щ�ӿڵ�list֧�ֿ��٣�ͨ���ǳ���ʱ�䣩������ʡ�
 * ����ӿڵ���ҪĿ��������һ����㷨�������ǵ���Ϊ���Ա����������˳���ȡ�б�ʱ���ṩ���õ�����
 *
 * <p>The best algorithms for manipulating ���� random access lists (such as
 * <tt>ArrayList</tt>) can produce quadratic /kw??dr?t?k/ behavior ����������Ϊ when applied to
 * sequential access lists ˳���ȡ�б� (such as <tt>LinkedList</tt>).  Generic list
 * algorithms are encouraged to check whether the given list is an
 * <tt>instanceof</tt> this interface before applying an algorithm that would
 * provide poor performance if it were applied to a sequential access list,
 * and to alter their behavior if necessary to guarantee acceptable
 * performance.
 * ������������б���ArrayList��������㷨��Ӧ����˳���ȡ�б�ʱ���п��ܲ�����������Ϊ��
 * �����㷨�б�����ڽ�ĳ���㷨Ӧ����˳���ȡ�б���ܵ��²������֮ǰ���ȼ��������б���
 * ��������ӿڵ�һ��ʵ����������Ҫʱȥ�ı���Щ�㷨����Ϊ�Ա�֤���ܡ�
 *
 * <p>It is recognized that ͨ����˵ the distinction between random and sequential
 * access is often fuzzy.  /?f?zi/ ģ����  For example, some <tt>List</tt> implementations
 * provide asymptotically linear access times �������Է���ʱ�� if they get huge, but constant
 * access times in practice.  Such a <tt>List</tt> implementation
 * should generally implement this interface.  As a rule of thumb ���ݾ���, a
 * <tt>List</tt> implementation should implement this interface if,
 * for typical instances of the class, this loop:
 *
 * ������ʺ�˳���ȡ֮��Ľ���ͨ����ģ���ġ����磬һЩListʵ���ڱ�úܴ�ʱ�ᵼ�½����ķ�
 * ���Է���ʱ�䣬��ʵ�����ǳ�������ʱ�䡣������Listʵ��ͨ����Ӧ��ʵ�ָýӿڡ�һ����˵��ĳ
 * ��Listʵ���������ĳЩ���͵����ʵ����˵���������� ��������ɶû˵,���ƾ���ָ������ʣ�����Ӧ��ʵ������ӿڣ�ѭ��
 * <pre>
 *     for (int i=0, n=list.size(); i &lt; n; i++)
 *         list.get(i);  // ֧�������ȡʹ��forѭ���϶��ǿ�ܶ�
 * </pre>
 * runs faster than this loop:
 * <pre>
 *     for (Iterator i=list.iterator(); i.hasNext(); )
 *         i.next();
 * </pre>

 * @since 1.4
 * @blog "https://www.cnblogs.com/V1haoge/p/10755424.html
 * @blog ���� "https://blog.csdn.net/liu20111590/article/details/87876331"
 */
public interface RandomAccess {
}
