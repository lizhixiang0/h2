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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.ibatis.cache.Cache;

/**
 * LRU (Least Recently Used) 最近最少使用缓存淘汰算法,核心思想就是会优先淘汰那些近期最少使用的缓存对象。基于 LinkedHashMap 覆盖其 removeEldestEntry 方法实现。
 *不能保证并发安全
 *
 * @author Clinton Begin
 */
public class LruCache implements Cache {

  private final Cache delegate;
  /**
   * 额外用了一个map才做lru，但是委托的Cache里面其实也是一个map，这样等于用2倍的内存实现lru功能
   */
  private Map<Object, Object> keyMap;
  private Object eldestKey;

  public LruCache(Cache delegate) {
    this.delegate = delegate;
    setSize(1024);
  }

  @Override
  public String getId() {
    return delegate.getId();
  }

  @Override
  public int getSize() {
    return delegate.getSize();
  }

  public void setSize(final int size) {
    /**
     * keyMap指向LinkedHashMap<Object,Object>的匿名子类
     * 在每次调用setSize方法时，都会创建一个新的该类型的对象，同时指定其容量大小。
     * 第三个参数为true代表Map中的键值对列表要按照访问顺序排序，即每次访问或者插入一个元素都会把元素放到链表末尾,这样不经常访问的键值肯定就在链表开头啦（值为false时按照插入顺序排序）
     * 重写了removeEldesEntry方法,用于获取在达到容量限制时被删除的key
     *
     */
    keyMap = new LinkedHashMap<Object, Object>(size, .75F, true) {
      private static final long serialVersionUID = 4267176411845948333L;
      /**
       * removeEldestEntry() 返回true则LinkedHashMap会删除最老键值
       * 所以重写 LinkedHashMap.removeEldestEntry方法,如果当前LinkedHashMap的容量大于设置的size,则返回true！同时将删除的最老键值抛出来！
       * @param eldest
       * @return
       */
      @Override
      protected boolean removeEldestEntry(Map.Entry<Object, Object> eldest) {
        boolean tooBig = size() > size;
        if (tooBig) {
          // 抛出被删除的最老键值
          eldestKey = eldest.getKey();
        }
        return tooBig;
      }
    };
  }

  @Override
  public void putObject(Object key, Object value) {
    delegate.putObject(key, value);
    /**
     * 增加新纪录后，判断是否要将最老元素移除
     */
    cycleKeyList(key);
  }

  @Override
  public Object getObject(Object key) {
    /**
     * get的时候调用一下LinkedHashMap.get，让经常访问的值移动到链表末尾
     */
    keyMap.get(key);
    return delegate.getObject(key);
  }

  @Override
  public Object removeObject(Object key) {
    return delegate.removeObject(key);
  }

  @Override
  public void clear() {
    delegate.clear();
    keyMap.clear();
  }

  @Override
  public ReadWriteLock getReadWriteLock() {
    return null;
  }

  private void cycleKeyList(Object key) {
    keyMap.put(key, key);
    /**
     * 假如eldestKey不为null，说明最老键值在LinkedHashMap中已经被移除了，所以我们还需要移除被委托的那个cache中的最老键值
     */
    if (eldestKey != null) {
      delegate.removeObject(eldestKey);
      eldestKey = null;
    }
  }

}
