/*
 * Copyright (c) 1997, 2012, Oracle and/or its affiliates. All rights reserved.
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
 * This class provides a skeletal implementation of the List interface to minimize the effort required to implement this interface backed by a "random access" data store (such as an array).
 * For sequential access data (such as a linked list), {@link AbstractSequentialList} should  be used in preference to this class.
 * 这个类提供了List接口的框架实现，以尽量最小化基于"随机访问"数据存储(例如数组)实现该接口所需的工作。
 *
 * To implement an unmodifiable list, the programmer needs only to extend this class and provide implementations for the get(int) and size() methods.
 *
 * To implement a modifiable list, the programmer must additionally override the set(int, Object) set(int, E) method (which otherwise throws an {@code UnsupportedOperationException}).
 * If the list is variable-size the programmer must additionally override the add(int, Object) add(int, E)} and remove(int) methods.
 * 如果列表是可变大小的，程序员还必须重写add(int, Object) add(int, E)}和remove(int)方法。
 *
 * The programmer should generally provide a void (no argument) and collection constructor, as per the recommendation in the Collection interface specification.
 *
 * Unlike the other abstract collection implementations, the programmer does not have to provide an iterator implementation;
 * the iterator and list iterator are implemented by this class, on top of 基于 the "random access" methods:get(int),set(int, Object) set(int, E),add(int, Object) add(int, E) and remove(int).
 *
 * The documentation for each non-abstract method in this class describes its implementation in detail.
 * Each of these methods may be overridden if the collection being implemented admits a more efficient implementation.
 *
 * This class is a member of the Java Collections Framework.
 *
 * @author  Josh Bloch
 * @author  Neal Gafter
 * @since 1.2
 */

public abstract class AbstractList<E> extends AbstractCollection<E> implements List<E> {
    /**
     * Sole constructor.  (For invocation by subclass constructors, typically implicit.
     * 用于由子类构造函数调用，通常是隐式的)
     */
    protected AbstractList() {
    }

    /**
     * Appends the specified element to the end of this list (optional operation).
     *
     * <p>Lists that support this operation may place limitations on what elements may be added to this list.
     * In particular, some lists will refuse to add null elements, and others will impose restrictions on the type of elements that may be added.
     * 特别是，一些列表将拒绝添加空元素，而其他列表将对可能添加的元素类型施加限制。
     *
     * List classes should clearly specify in their documentation any restrictions  on what elements may be added.
     *
     * <p>This implementation calls {@code add(size(), e)}.
     *
     * <p>Note that this implementation throws an {@code UnsupportedOperationException} unless {@link #add(int, Object) add(int, E)} is overridden.
     *
     * @param e element to be appended to this list
     * @return {@code true} (as specified by {@link Collection#add})
     * @throws UnsupportedOperationException if the {@code add} operation is not supported by this list
     * @throws ClassCastException if the class of the specified element prevents it from being added to this list
     * @throws NullPointerException if the specified element is null and this list does not permit null elements
     * @throws IllegalArgumentException if some property of this element prevents it from being added to this list
     */
    public boolean add(E e) {
        add(size(), e);
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * @throws IndexOutOfBoundsException {@inheritDoc}
     */
    abstract public E get(int index);

    /**
     * {@inheritDoc}
     *
     * <p>This implementation always throws an {@code UnsupportedOperationException}.
     *
     */
    public E set(int index, E element) {
        throw new UnsupportedOperationException();
    }

    /**
     * {@inheritDoc}
     *
     * <p>This implementation always throws an {@code UnsupportedOperationException}.
     *
     */
    public void add(int index, E element) {
        throw new UnsupportedOperationException();
    }

    /**
     * {@inheritDoc}
     *
     * <p>This implementation always throws an {@code UnsupportedOperationException}.
     *
     */
    public E remove(int index) {
        throw new UnsupportedOperationException();
    }


    // Search Operations

    /**
     * {@inheritDoc}
     *
     * This implementation first gets a list iterator with listIterator().
     * Then, it iterates over the list until the specified element is found or the end of the list is reached.
     *
     */
    public int indexOf(Object o) {
        ListIterator<E> it = listIterator();
        if (o==null) {
            while (it.hasNext())
                if (it.next()==null)
                    return it.previousIndex();
        } else {
            while (it.hasNext())
                if (o.equals(it.next()))
                    return it.previousIndex();
        }
        return -1;
    }

    /**
     * {@inheritDoc}
     *
     * This implementation first gets a list iterator that points to the end of the list with listIterator(size()).
     * Then, it iterates backwards over the list until the specified element is found, or the beginning of the list is reached.
     *
     */
    public int lastIndexOf(Object o) {
        ListIterator<E> it = listIterator(size());
        if (o==null) {
            while (it.hasPrevious())
                if (it.previous()==null)
                    return it.nextIndex();
        } else {
            while (it.hasPrevious())
                if (o.equals(it.previous()))
                    return it.nextIndex();
        }
        return -1;
    }


    // Bulk Operations   批量操作

    /**
     * Removes all of the elements from this list (optional operation).
     * The list will be empty after this call returns.
     *
     * This implementation calls removeRange(0, size()).
     *
     * Note that this implementation throws an UnsupportedOperationException unless remove(int index) or removeRange(int fromIndex, int toIndex) is overridden.
     *
     * @throws UnsupportedOperationException if the {@code clear} operation is not supported by this list
     */
    public void clear() {
        removeRange(0, size());
    }

    /**
     * {@inheritDoc}
     *
     * This implementation gets an iterator over the specified collection and iterates over it,
     * inserting the elements obtained from the iterator into this list at the appropriate position, one at a time,using add(int, E).
     * Many implementations will override this method for efficiency.
     *
     * <p>Note that this implementation throws an UnsupportedOperationException unless add(int, Object) add(int, E) is overridden.
     *
     */
    public boolean addAll(int index, Collection<? extends E> c) {
        rangeCheckForAdd(index);
        boolean modified = false;
        for (E e : c) {
            add(index++, e);
            modified = true;
        }
        return modified;
    }


    // Iterators  迭代器

    /**
     * Returns an iterator over the elements in this list in proper sequence. 返回一个迭代器，依次遍历列表中的元素   sequence n. [数][计] 序列；顺序；续发事件 vt. 按顺序排好
     * This implementation returns a straightforward implementation of the iterator interface, relying on the backing list's size(),get(int), and remove(int) methods.
     * Note that the iterator returned by this method will throw an UnsupportedOperationException in response to its remove method unless the list's remove(int) method is overridden.
     * This implementation can be made to throw runtime exceptions in the face of concurrent modification, as described in the specification for the (protected) modCount field.
     * 这种实现类在面对并发修改时抛出运行时异常，正如(受保护的)modCount字段的规范中所描述的那样。
     *
     * @return an iterator over the elements in this list in proper sequence
     */
    public Iterator<E> iterator() {
        return new Itr();
    }

    /**
     * {@inheritDoc}
     *
     * <p>This implementation returns {@code listIterator(0)}.
     *
     */
    public ListIterator<E> listIterator() {
        return listIterator(0);
    }

    /**
     * {@inheritDoc}
     *
     * This implementation returns a straightforward implementation of the ListIterator interface that extends the implementation of the Iterator interface returned by the iterator() method.
     * The ListIterator implementation relies on the backing list's get(int), set(int, E),add(int, E) and remove(int) methods.
     *
     * Note that the list iterator returned by this implementation will throw an UnsupportedOperationException in response to its remove, set and  add methods unless the
     * list's remove(int), set(int, E), and add(int, E) methods are overridden.
     *
     * This implementation can be made to throw runtime exceptions in the face of concurrent modification, as described in the specification for the (protected) modCount field.
     *
     */
    public ListIterator<E> listIterator(final int index) {
        rangeCheckForAdd(index);

        return new ListItr(index);
    }

    private class Itr implements Iterator<E> {
        /**
         * Index of element to be returned by subsequent call to next.
         * 调用next将返回的元素的索引,也就是下一个元素的索引，默认初始化为0
         */
        int cursor = 0;

        /**
         * Index of element returned by most recent call to next or previous.  Reset to -1 if this element is deleted by a call to remove.
         * 最近一次调用next或previous时返回的元素索引。也就是上次访问的元素的位置,如果该元素被调用remove删除，则重置为-1。
         */
        int lastRet = -1;

        /**
         * The modCount value that the iterator believes that the backing List should have. 迭代器认为List应该具有的modCount值
         * If this expectation is violated, the iterator has detected concurrent modification.  如果违背了这个期望，迭代器就检测到并发修改
         */
        int expectedModCount = modCount;

        public boolean hasNext() {
            return cursor != size();
        }

        public E next() {
            checkForComodification();
            try {
                int i = cursor;
                E next = get(i);
                lastRet = i;
                cursor = i + 1;
                return next;
            } catch (IndexOutOfBoundsException e) {
                checkForComodification();
                throw new NoSuchElementException();
            }
        }

        public void remove() {
            if (lastRet < 0)
                throw new IllegalStateException();
            checkForComodification();

            try {
                AbstractList.this.remove(lastRet);
                if (lastRet < cursor)
                    cursor--;
                lastRet = -1;
                expectedModCount = modCount;
            } catch (IndexOutOfBoundsException e) {
                throw new ConcurrentModificationException();
            }
        }

        final void checkForComodification() {
            if (modCount != expectedModCount)
                throw new ConcurrentModificationException();
        }
    }

    private class ListItr extends Itr implements ListIterator<E> {
        ListItr(int index) {
            cursor = index;
        }

        public boolean hasPrevious() {
            return cursor != 0;
        }

        public E previous() {
            checkForComodification();
            try {
                int i = cursor - 1;
                E previous = get(i);
                lastRet = cursor = i;
                return previous;
            } catch (IndexOutOfBoundsException e) {
                checkForComodification();
                throw new NoSuchElementException();
            }
        }

        public int nextIndex() {
            return cursor;
        }

        public int previousIndex() {
            return cursor-1;
        }

        public void set(E e) {
            if (lastRet < 0)
                throw new IllegalStateException();
            checkForComodification();

            try {
                AbstractList.this.set(lastRet, e);
                expectedModCount = modCount;
            } catch (IndexOutOfBoundsException ex) {
                throw new ConcurrentModificationException();
            }
        }

        public void add(E e) {
            checkForComodification();

            try {
                int i = cursor;
                AbstractList.this.add(i, e);
                lastRet = -1;
                cursor = i + 1;
                expectedModCount = modCount;
            } catch (IndexOutOfBoundsException ex) {
                throw new ConcurrentModificationException();
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>This implementation returns a list that subclasses
     * {@code AbstractList}.  The subclass stores, in private fields, the
     * offset of the subList within the backing list, the size of the subList
     * (which can change over its lifetime), and the expected
     * {@code modCount} value of the backing list.  There are two variants
     * of the subclass, one of which implements {@code RandomAccess}.
     * If this list implements {@code RandomAccess} the returned list will
     * be an instance of the subclass that implements {@code RandomAccess}.
     *
     * <p>The subclass's {@code set(int, E)}, {@code get(int)},
     * {@code add(int, E)}, {@code remove(int)}, {@code addAll(int,
     * Collection)} and {@code removeRange(int, int)} methods all
     * delegate to the corresponding methods on the backing abstract list,
     * after bounds-checking the index and adjusting for the offset.  The
     * {@code addAll(Collection c)} method merely returns {@code addAll(size,
     * c)}.
     *
     * <p>The {@code listIterator(int)} method returns a "wrapper object"
     * over a list iterator on the backing list, which is created with the
     * corresponding method on the backing list.  The {@code iterator} method
     * merely returns {@code listIterator()}, and the {@code size} method
     * merely returns the subclass's {@code size} field.
     *
     * <p>All methods first check to see if the actual {@code modCount} of
     * the backing list is equal to its expected value, and throw a
     * {@code ConcurrentModificationException} if it is not.
     *
     * @throws IndexOutOfBoundsException if an endpoint index value is okut of range
     *         {@code (fromIndex < 0 || toIndex > size)}
     * @throws IllegalArgumentException if the endpoint indices are out of order
     *         {@code (fromIndex > toIndex)}
     */
    public List<E> subList(int fromIndex, int toIndex) {
        return (this instanceof RandomAccess ?
                new RandomAccessSubList<>(this, fromIndex, toIndex) :
                new SubList<>(this, fromIndex, toIndex));
    }

    // Comparison and hashing

    /**
     * Compares the specified object with this list for equality.   比较指定对象与列表是否相等
     * Returns true if and only if the specified object is also a list, both lists have the same size, and all corresponding pairs of elements in the two lists are equal.
     * 当且仅当指定的对象也是一个列表，两个列表具有相同的大小，且两个列表中所有对应的元素对都相等时返回true
     * (Two elements  e1 and e2 are equal if (e1==null ? e2==null :e1.equals(e2)).)
     * In other words, two lists are defined to be equal if they contain the same elements in the same order. 换句话说，如果两个列表以相同的顺序包含相同的元素，那么它们就被定义为相等的
     *
     * This implementation first checks if the specified object is this list.
     * If so, it returns  true;
     * if not, it checks if the specified object is a list.
     * If not, it returns false;
     * if so,it iterates over both lists, comparing corresponding pairs of elements.
     * If any comparison returns false, this method returns false.
     *
     * If either iterator runs out of elements before the other it returns false (as the lists are of unequal length);
     * otherwise it returns  true when the iterations complete.
     *
     * @param o the object to be compared for equality with this list
     * @return {@code true} if the specified object is equal to this list
     */
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof List))
            return false;

        ListIterator<E> e1 = listIterator();
        ListIterator<?> e2 = ((List<?>) o).listIterator();
        while (e1.hasNext() && e2.hasNext()) {
            E o1 = e1.next();
            Object o2 = e2.next();
            if (!(o1==null ? o2==null : o1.equals(o2)))
                return false;
        }
        return !(e1.hasNext() || e2.hasNext());
    }

    /**
     * Returns the hash code value for this list.
     *
     * <p>This implementation uses exactly the code that is used to define the
     * list hash function in the documentation for the {@link List#hashCode}
     * method.
     *
     * @return the hash code value for this list
     */
    public int hashCode() {
        int hashCode = 1;
        for (E e : this)
            hashCode = 31*hashCode + (e==null ? 0 : e.hashCode());
        return hashCode;
    }

    /**
     * Removes from this list all of the elements whose index is between
     * {@code fromIndex}, inclusive, and {@code toIndex}, exclusive.
     * Shifts any succeeding elements to the left (reduces their index).
     * This call shortens the list by {@code (toIndex - fromIndex)} elements.
     * (If {@code toIndex==fromIndex}, this operation has no effect.)
     *
     * <p>This method is called by the {@code clear} operation on this list
     * and its subLists.  Overriding this method to take advantage of
     * the internals of the list implementation can <i>substantially</i>
     * improve the performance of the {@code clear} operation on this list
     * and its subLists.
     *
     * <p>This implementation gets a list iterator positioned before
     * {@code fromIndex}, and repeatedly calls {@code ListIterator.next}
     * followed by {@code ListIterator.remove} until the entire range has
     * been removed.  <b>Note: if {@code ListIterator.remove} requires linear
     * time, this implementation requires quadratic time.</b>
     *
     * @param fromIndex index of first element to be removed
     * @param toIndex index after last element to be removed
     */
    protected void removeRange(int fromIndex, int toIndex) {
        ListIterator<E> it = listIterator(fromIndex);
        for (int i=0, n=toIndex-fromIndex; i<n; i++) {
            it.next();
            it.remove();
        }
    }




    /**
     * The number of times this list has been structurally modified.  这个变量用来记录列表被结构性修改的次数
     * Structural modifications are those that change the size of the list, or otherwise perturb it in such a fashion that iterations in progress may yield incorrect results.
     * 结构修改是指改变列表的大小，或者以某种方式扰乱列表，从而使得正在进行的迭代可能产生不正确的结果 (自己原来的错误翻译：或者以迭代过程中产生错误结果的方式来扰乱列表)
     *
     * This field is used by the iterator and list iterator implementation returned by the iterator and listIterator methods.
     * If the value of this field changes unexpectedly, the iterator (or list iterator) will throw a ConcurrentModificationException in response to the  next,  remove, previous, set or  add operations.
     * 这个字段通常会在迭代器 iterator 和 listIterator 返回的结果中使用，如果 modCount 和预期的值不一样，会抛出 ConcurrentModificationException 异常。
     *
     * This provides fail-fast behavior, rather than non-deterministic behavior in the face of concurrent modification during iteration.
     * 这提供了快速失败的行为，而不是在迭代过程中面对并发修改时的不确定性行为。
     *
     * Use of this field by subclasses is optional.  子类对该字段的使用是可选的
     * If an implementation does not wish to provide fail-fast iterators, this field may be ignored.  如果子类不希望提供快速失败迭代器，则可以忽略该字段
     *
     * If a subclass wishes to provide fail-fast iterators (and list iterators), then it merely has to increment this field in its  add(int, E) and remove(int) methods and any other methods that it overrides that result in structural modifications to the list.
     * 如果子类希望提供快速失败迭代器，那么它只需在其add(int, E)和remove(int)方法以及它覆盖的导致列表结构修改的任何其他方法中增加该字段。
     *
     * A single call to add(int, E) or remove(int) must add no more than one to this field, or the iterators (and list iterators) will throw bogus ConcurrentModificationExceptions.
     * 调用add(int, E)或remove(int)必须让该字段自增一，否则迭代器将抛出虚假的并发修改异常
     */
    protected transient int modCount = 0;

    private void rangeCheckForAdd(int index) {
        if (index < 0 || index > size())
            throw new IndexOutOfBoundsException(outOfBoundsMsg(index));
    }

    private String outOfBoundsMsg(int index) {
        return "Index: "+index+", Size: "+size();
    }
}

class SubList<E> extends AbstractList<E> {
    private final AbstractList<E> l;
    private final int offset;
    private int size;

    SubList(AbstractList<E> list, int fromIndex, int toIndex) {
        if (fromIndex < 0)
            throw new IndexOutOfBoundsException("fromIndex = " + fromIndex);
        if (toIndex > list.size())
            throw new IndexOutOfBoundsException("toIndex = " + toIndex);
        if (fromIndex > toIndex)
            throw new IllegalArgumentException("fromIndex(" + fromIndex +
                                               ") > toIndex(" + toIndex + ")");
        l = list;
        offset = fromIndex;
        size = toIndex - fromIndex;
        this.modCount = l.modCount;
    }

    public E set(int index, E element) {
        rangeCheck(index);
        checkForComodification();
        return l.set(index+offset, element);
    }

    public E get(int index) {
        rangeCheck(index);
        checkForComodification();
        return l.get(index+offset);
    }

    public int size() {
        checkForComodification();
        return size;
    }

    public void add(int index, E element) {
        rangeCheckForAdd(index);
        checkForComodification();
        l.add(index+offset, element);
        this.modCount = l.modCount;
        size++;
    }

    public E remove(int index) {
        rangeCheck(index);
        checkForComodification();
        E result = l.remove(index+offset);
        this.modCount = l.modCount;
        size--;
        return result;
    }

    protected void removeRange(int fromIndex, int toIndex) {
        checkForComodification();
        l.removeRange(fromIndex+offset, toIndex+offset);
        this.modCount = l.modCount;
        size -= (toIndex-fromIndex);
    }

    public boolean addAll(Collection<? extends E> c) {
        return addAll(size, c);
    }

    public boolean addAll(int index, Collection<? extends E> c) {
        rangeCheckForAdd(index);
        int cSize = c.size();
        if (cSize==0)
            return false;

        checkForComodification();
        l.addAll(offset+index, c);
        this.modCount = l.modCount;
        size += cSize;
        return true;
    }

    public Iterator<E> iterator() {
        return listIterator();
    }

    public ListIterator<E> listIterator(final int index) {
        checkForComodification();
        rangeCheckForAdd(index);

        return new ListIterator<E>() {
            private final ListIterator<E> i = l.listIterator(index+offset);

            public boolean hasNext() {
                return nextIndex() < size;
            }

            public E next() {
                if (hasNext())
                    return i.next();
                else
                    throw new NoSuchElementException();
            }

            public boolean hasPrevious() {
                return previousIndex() >= 0;
            }

            public E previous() {
                if (hasPrevious())
                    return i.previous();
                else
                    throw new NoSuchElementException();
            }

            public int nextIndex() {
                return i.nextIndex() - offset;
            }

            public int previousIndex() {
                return i.previousIndex() - offset;
            }

            public void remove() {
                i.remove();
                SubList.this.modCount = l.modCount;
                size--;
            }

            public void set(E e) {
                i.set(e);
            }

            public void add(E e) {
                i.add(e);
                SubList.this.modCount = l.modCount;
                size++;
            }
        };
    }

    public List<E> subList(int fromIndex, int toIndex) {
        return new SubList<>(this, fromIndex, toIndex);
    }

    private void rangeCheck(int index) {
        if (index < 0 || index >= size)
            throw new IndexOutOfBoundsException(outOfBoundsMsg(index));
    }

    private void rangeCheckForAdd(int index) {
        if (index < 0 || index > size)
            throw new IndexOutOfBoundsException(outOfBoundsMsg(index));
    }

    private String outOfBoundsMsg(int index) {
        return "Index: "+index+", Size: "+size;
    }

    private void checkForComodification() {
        if (this.modCount != l.modCount)
            throw new ConcurrentModificationException();
    }
}

class RandomAccessSubList<E> extends SubList<E> implements RandomAccess {
    RandomAccessSubList(AbstractList<E> list, int fromIndex, int toIndex) {
        super(list, fromIndex, toIndex);
    }

    public List<E> subList(int fromIndex, int toIndex) {
        return new RandomAccessSubList<>(this, fromIndex, toIndex);
    }
}
