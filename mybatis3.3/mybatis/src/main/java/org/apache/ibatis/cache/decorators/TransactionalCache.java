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
 *        只有调用TransactionalCache的commit()方法时，所有的更新操作才会真正同步到缓存对象中。
 *        这样的话，就会存在一个问题：
 *        若事务被设置为自动提交（autoCommit=true）,写操作会更新RDBMS（关系型数据库管理系统），但不会清空缓存对象（因为自动提交不会调用commit方法），
 *        这样就会产生数据库与缓存中数据不一致的情况。如果缓存没有过期失效的机制，那么问题会很严重。
 *
 *        主要作用是保存SqlSession在事务中需要向某个二级缓存提交的缓存数据（因为事务过程中的数据可能会回滚，所以不能直接把数据就提交二级缓存，而是暂存在TransactionalCache中，
 *        在事务提交后再将过程中存放在其中的数据提交到二级缓存，如果事务回滚，则将数据清除掉）
 */
public class TransactionalCache implements Cache {

  private Cache delegate;

  /**
   * 如果此值为true，则调用commit时会进行清空缓存的操作,初始为false
   * 只有事务中包含更新操作时，此值才会为true,否则只需要覆盖指定key/value的更新即可，（覆盖分为删除和添加两步操作）
   */
  private boolean clearOnCommit;

  /**
   * 执行commit方法时,会将entriesToAddOnCommit（Add暂存区）中的缓存项都写入到缓存中
   * 注:调用putObject方法时,缓存项不会直接添加到缓存中，而是先将缓存项存入到这个暂存区
   */
  private Map<Object, Object> entriesToAddOnCommit;
  /**
   * 执行commit方法时,会将entriesMissedInCache（Missed暂存区）中的缓存项都从缓存中移除
   * 注：调用removeObject时,不会直接从缓存中移除此缓存项，而是先将缓存项存入到这个缓存区
   */
  private Set<Object> entriesMissedInCache;

  public TransactionalCache(Cache delegate) {
    this.delegate = delegate;
    //默认commit时不清缓存
    this.clearOnCommit = false;
    this.entriesToAddOnCommit = new HashMap<Object, Object>();
    this.entriesMissedInCache = new HashSet<Object>();
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
  public Object getObject(Object key) {
    // issue #116
    Object object = delegate.getObject(key);
    if (object == null) {
      entriesMissedInCache.add(key);
    }
    // issue #146
    if (clearOnCommit) {
      return null;
    } else {
      return object;
    }
  }

  @Override
  public ReadWriteLock getReadWriteLock() {
    return null;
  }

  @Override
  public void putObject(Object key, Object object) {
    entriesToAddOnCommit.put(key, object);
  }

  @Override
  public Object removeObject(Object key) {
    return null;
  }

  @Override
  public void clear() {
    clearOnCommit = true;
    entriesToAddOnCommit.clear();
  }

  //多了commit方法，提供事务功能
  public void commit() {
    if (clearOnCommit) {
      delegate.clear();
    }
    flushPendingEntries();
    reset();
  }

  public void rollback() {
    unlockMissedEntries();
    reset();
  }

  private void reset() {
    clearOnCommit = false;
    entriesToAddOnCommit.clear();
    entriesMissedInCache.clear();
  }

  private void flushPendingEntries() {
    for (Map.Entry<Object, Object> entry : entriesToAddOnCommit.entrySet()) {
      delegate.putObject(entry.getKey(), entry.getValue());
    }
    for (Object entry : entriesMissedInCache) {
      if (!entriesToAddOnCommit.containsKey(entry)) {
        delegate.putObject(entry, null);
      }
    }
  }

  private void unlockMissedEntries() {
    for (Object entry : entriesMissedInCache) {
      delegate.putObject(entry, null);
    }
  }

}
