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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.ibatis.cache.Cache;

/**
 * The 2nd level cache transactional buffer.
 *
 * This class holds all cache entries that are to be added to the 2nd level cache during a Session.
 * Entries are sent to the cache when commit is called or discarded if the Session is rolled back.
 * Blocking cache support has been added. Therefore any get() that returns a cache miss
 * will be followed by a put() so any lock associated with the key can be released.
 *
 * @author Clinton Begin
 * @author Eduardo Macarron
 * @blog "https://blog.csdn.net/qq_28126793/article/details/85726066
 * @简介   TransactionalCache比其他Cache对象多出了2个方法：commit()和rollback()。
 *        TransactionalCache对象内部存在暂存区，所有对缓存对象的写操作都不会直接作用于缓存对象，而是被保存在暂存区，
 *        在事务提交(调用TransactionalCache的commit()方法)后再将过程中存放在其中的数据提交到二级缓存，如果事务回滚（调用rollback()方法），则将数据清除掉
 *        这样的话，就会存在一个问题：
 *        若事务被设置为自动提交（autoCommit=true）,写操作会更新RDBMS（关系型数据库管理系统），但不会清空缓存对象（因为自动提交不会调用commit方法），
 *        这样就会产生数据库与缓存中数据不一致的情况。如果缓存没有过期失效的机制，那么问题会很严重。
 *        这里需要验证，自动提交会不会触发commit方法？
 *，
 *
 */
public class TransactionalCache implements Cache {

  private Cache delegate;

  /**
   * 初始为false，调用commit时，覆盖指定的key->value即可
   * 只有事务中包含update更新操作时，此值才会为true，调用commit时会先清空二级缓存中的所有缓存项。
   */
  private boolean clearOnCommit;

  /**
   * 执行commit方法时,会将entriesToAddOnCommit（Add暂存区）中的缓存项都写入到缓存中
   * 注:调用putObject方法时,缓存项不会直接添加到缓存中，而是先将缓存项存入到这个暂存区
   */
  private Map<Object, Object> entriesToAddOnCommit;
  /**
   * 执行commit方法时,判断entriesMissedInCache（Missed暂存区）中的缓存项在暂存区中是否存在，不存在则还将该CacheKey置为null
   * 注：调用getObject方法时,记录缓存未命中的CacheKey对象,目的是为了防止缓存穿透
   * 缓存穿透：缓存穿透是指用户不断对缓存和数据库中都没有的数据发起请求，如发起为id为“-1”的数据或id为特别大不存在的数据。这时的用户很可能是攻击者，攻击会导致数据库压力过大。
   *          所以我们在缓存中将此数据设置为null,请求就打不到数据库上去。
   */
  private Set<Object> entriesMissedInCache;

  public TransactionalCache(Cache delegate) {
    this.delegate = delegate;
    /**
     * 默认commit时不清缓存
     */
    this.clearOnCommit = false;
    this.entriesToAddOnCommit = new HashMap<>();
    this.entriesMissedInCache = new HashSet<>();
  }

  @Override
  public String getId() {
    return delegate.getId();
  }

  @Override
  public int getSize() {
    return delegate.getSize();
  }

  @Override
  public void putObject(Object key, Object object) {
    /**
     * 缓存在entriesToAddOnCommit中等待事务提交
     */
    entriesToAddOnCommit.put(key, object);
  }

  @Override
  public Object getObject(Object key) {
    Object object = delegate.getObject(key);
    if (object == null) {
      entriesMissedInCache.add(key);
    }
    if (clearOnCommit) {
      return null;
    } else {
      return object;
    }
  }

  @Override
  public Object removeObject(Object key) {
    return null;
  }

  @Override
  public void clear() {
    /**
     * 这个clear什么情况下会调用到？
     */
    clearOnCommit = true;
    entriesToAddOnCommit.clear();
  }

  public void commit() {
    if (clearOnCommit) {
      /**
       * 如果clearOnCommit为true则，事务提交前清空二级缓存
       */
      delegate.clear();
    }
    /**
     * 将entriesToAddOnCommit、entriesMissedInCache添加至二级缓存中
     */
    flushPendingEntries();
    /**
     * 回到事务最初的状态,等待下一次事务的开始
     */
    reset();
  }

  public void rollback() {
    /**
     * 将entriesMissedInCache添加进二级缓存
     */
    unlockMissedEntries();
    /**
     * 回到事务最初的状态，等待下一次事务的开始
     */
    reset();
  }

  /**
   * 重置clearOnCommit=false,清空entriesToAddOnCommit、entriesMissedInCache
   */
  private void reset() {
    clearOnCommit = false;
    entriesToAddOnCommit.clear();
    entriesMissedInCache.clear();
  }

  private void flushPendingEntries() {
    for (Map.Entry<Object, Object> entry : entriesToAddOnCommit.entrySet()) {
      delegate.putObject(entry.getKey(), entry.getValue());
    }
    /**
     *  将未命中的缓存且暂存区不存在的缓存项置为null, 自己觉得是为了防止缓存穿透
     */
    for (Object key : entriesMissedInCache) {
      if (!entriesToAddOnCommit.containsKey(key)) {
        delegate.putObject(key, null);
      }
    }
  }

  private void unlockMissedEntries() {
    for (Object entry : entriesMissedInCache) {
      delegate.putObject(entry, null);
    }
  }

  @Override
  public ReadWriteLock getReadWriteLock() {
    return null;
  }


}
