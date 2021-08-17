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
 *  RandomAccess是一个空接口，而空接口的作用一般是起到一个标识的作用。
 * 通俗点讲，就是判断一个list是否实现了RandomAccess接口，如果实现了，采用简单的for循环进行访问速度比较快。
 * 如果未实现RandomAccess接口，则采用iterator循环访问速度比较快。
 *
 * Marker interface 标记接口 used by <tt>List</tt> implementations to indicate that
 * they support fast (generally constant time) random access 随机存取.  The primary
 * purpose of this interface is to allow generic algorithms 泛型算法 to alter their
 * behavior to provide good performance when applied to either random or
 * sequential access lists 应用于随机或顺序存储列表.
 *
 * List实现所使用的标记接口，用来表明实现了这些接口的list支持快速（通常是常数时间）随机访问。
 * 这个接口的主要目的是允许一般的算法更改它们的行为，以便在随机或者顺序存取列表时能提供更好的性能
 *
 * <p>The best algorithms for manipulating 操纵 random access lists (such as
 * <tt>ArrayList</tt>) can produce quadratic /kw??dr?t?k/ behavior 产生二次行为 when applied to
 * sequential access lists 顺序存取列表 (such as <tt>LinkedList</tt>).  Generic list
 * algorithms are encouraged to check whether the given list is an
 * <tt>instanceof</tt> this interface before applying an algorithm that would
 * provide poor performance if it were applied to a sequential access list,
 * and to alter their behavior if necessary to guarantee acceptable
 * performance.
 * 操作随机访问列表（如ArrayList）的最佳算法在应用于顺序存取列表时，有可能产生二次项行为。
 * 泛型算法列表鼓励在将某个算法应用于顺序存取列表可能导致差的性能之前，先检查给定的列表是
 * 否是这个接口的一个实例，并在需要时去改变这些算法的行为以保证性能。
 *
 * <p>It is recognized that 通常来说 the distinction between random and sequential
 * access is often fuzzy.  /?f?zi/ 模糊的  For example, some <tt>List</tt> implementations
 * provide asymptotically linear access times 渐近线性访问时间 if they get huge, but constant
 * access times in practice.  Such a <tt>List</tt> implementation
 * should generally implement this interface.  As a rule of thumb 根据经验, a
 * <tt>List</tt> implementation should implement this interface if,
 * for typical instances of the class, this loop:
 *
 * 随机访问和顺序存取之间的界限通常是模糊的。例如，一些List实现在变得很大时会导致渐进的非
 * 线性访问时间，但实际上是常量访问时间。这样的List实现通常都应该实现该接口。一般来说，某
 * 个List实现如果（对某些典型的类的实例来说）满足条件 （条件是啥没说,估计就是指随机访问），就应该实现这个接口：循环
 * <pre>
 *     for (int i=0, n=list.size(); i &lt; n; i++)
 *         list.get(i);  // 支持随机存取使用for循环肯定是快很多
 * </pre>
 * runs faster than this loop:
 * <pre>
 *     for (Iterator i=list.iterator(); i.hasNext(); )
 *         i.next();
 * </pre>

 * @since 1.4
 * @blog "https://www.cnblogs.com/V1haoge/p/10755424.html
 * @blog 测试 "https://blog.csdn.net/liu20111590/article/details/87876331"
 */
public interface RandomAccess {
}
