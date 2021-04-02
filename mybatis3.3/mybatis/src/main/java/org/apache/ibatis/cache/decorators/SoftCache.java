/*
 *    Copyright 2009-2014 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package org.apache.ibatis.cache.decorators;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.Deque;
import java.util.LinkedList;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.ibatis.cache.Cache;

/**
 * 强引用（hard link）、软引用（soft link）、弱引用、幻象引用有什么区别?"https://www.cnblogs.com/zyjimmortalp/p/12639410.html、
 * 软引用缓存,核心是SoftReference
 * @author Clinton Begin
 */
public class SoftCache implements Cache {
  /**
   * 确保最近使用的一部分缓存项不会被GC回收(默认不超过256个)，通过将其value添加到hardLinksToAvoidGarbageCollection集合中来实现的
   */
  private final Deque<Object> hardLinksToAvoidGarbageCollection;
  /**
   * 引用队列，用于记录GC回收的缓存项所对应的SoftEntry对象
   */
  private final ReferenceQueue<Object> queueOfGarbageCollectedEntries;
  /**
   * 底层被修饰的cache对象
   */
  private final Cache delegate;
  /**
   * 强引用的个数,默认256
   */
  private int numberOfHardLinks;

  public SoftCache(Cache delegate) {
    this.delegate = delegate;
    this.numberOfHardLinks = 256;
    this.hardLinksToAvoidGarbageCollection = new LinkedList<>();
    this.queueOfGarbageCollectedEntries = new ReferenceQueue<>();
  }

  @Override
  public String getId() {
    return delegate.getId();
  }

  @Override
  public int getSize() {
    removeGarbageCollectedItems();
    return delegate.getSize();
  }


  public void setSize(int size) {
    this.numberOfHardLinks = size;
  }

  @Override
  public void putObject(Object key, Object value) {
    removeGarbageCollectedItems();
    /**
     * putObject存了一个SoftReference,这样当JVM认为内存不足时(可以认为是OOM之前),才会去试图回收软引用指向的对象,从而避免因为缓存数据太多导致OOM
     */
    delegate.putObject(key, new SoftEntry(key, value, queueOfGarbageCollectedEntries));
  }

  @Override
  public Object getObject(Object key) {
    Object result = null;
    /**
     * 查找对应的缓存项
     */
    @SuppressWarnings("unchecked") // assumed delegate cache is totally managed by this cache
    SoftReference<Object> softReference = (SoftReference<Object>) delegate.getObject(key);
    if (softReference != null) {
      /**
       * 假如没有被GC回收就调用get方法
       */
      result = softReference.get();
      if (result == null) {
        /**
         * 已经被GC回收,get()返回对象为null，则删除此缓存项
         */
        delegate.removeObject(key);
      } else {
        /**
         * 还没被GC回收,即get()返回值不为null,则将此对象放到hardLinksToAvoidGarbageCollection,相当于强制将软引用变为硬引用！在OOM之前GC无法自动回收该对象
         */
        // See #586 (and #335) modifications need more than a read lock
        synchronized (hardLinksToAvoidGarbageCollection) {
          hardLinksToAvoidGarbageCollection.addFirst(result);
          if (hardLinksToAvoidGarbageCollection.size() > numberOfHardLinks) {
            /**
             * 先进先出，最多存储256个硬引用
             */
            hardLinksToAvoidGarbageCollection.removeLast();
          }
        }
      }
    }
    return result;
  }

  @Override
  public Object removeObject(Object key) {
    removeGarbageCollectedItems();
    return delegate.removeObject(key);
  }

  @Override
  public void clear() {
    synchronized (hardLinksToAvoidGarbageCollection) {
      hardLinksToAvoidGarbageCollection.clear();
    }
    removeGarbageCollectedItems();
    delegate.clear();
  }

  @Override
  public ReadWriteLock getReadWriteLock() {
    return null;
  }

  private void removeGarbageCollectedItems() {
    SoftEntry sv;
    /**
     * 轮询队列queueOfGarbageCollectedEntries，查看是否存在可用的引用对象。如果存在则从该队列中移除此对象并返回此对象
     * 这个引用对象要注意下不是我们实际使用的那个对象，而是实际使用的那个对象外面包裹的那个对象，这个对象是没有被GC自动清理的。
     */
    while ((sv = (SoftEntry) queueOfGarbageCollectedEntries.poll()) != null) {
      delegate.removeObject(sv.key);
    }
  }

  private static class SoftEntry extends SoftReference<Object> {
    private final Object key;

    /**
     * garbageCollectionQueue的意义在于，如果有对象即将被回收，那么相应的reference对象就会被放到这个queue里,我们可以在外部对这个queue进行监控。
     * 注：如果我们在创建一个引用对象（SoftEntry）时，指定了ReferenceQueue，那么当引用对象指向的对象达到合适的状态（根据引用类型不同而不同）时，GC 会把引用对象本身添加到这个队列中，方便我们处理它，
     * 因为虽然引用对象指向的对象 GC 会自动清理，但是引用对象本身也是对象（是对象就占用一定资源），所以需要我们自己清理。
     * @blog "https://www.jianshu.com/p/f86d3a43eec5
     * @param value
     * @param garbageCollectionQueue
     */
    SoftEntry(Object key, Object value, ReferenceQueue<Object> garbageCollectionQueue) {
      super(value, garbageCollectionQueue);
      this.key = key;
    }
  }

}
