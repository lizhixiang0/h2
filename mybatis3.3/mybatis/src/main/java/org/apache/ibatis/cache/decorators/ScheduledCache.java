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

import java.util.concurrent.locks.ReadWriteLock;

import org.apache.ibatis.cache.Cache;

/**
 * 定时调度缓存,目的是每一小时清空一下缓存
 * @author Clinton Begin
 */
public class ScheduledCache implements Cache {

  private Cache delegate;
  protected long clearInterval;
  protected long lastClear;

  public ScheduledCache(Cache delegate) {
    this.delegate = delegate;
    /**
     * 1小时
     */
    this.clearInterval = 60 * 60 * 1000;
    this.lastClear = System.currentTimeMillis();
  }

  /**
   * 自己设置清除时间
   * @param clearInterval
   */
  public void setClearInterval(long clearInterval) {
    this.clearInterval = clearInterval;
  }

  /**
   * 执行getSize、putObject、getObject、removeObject 都会调用这个这个方法
   * 如果到时间了，清空一下缓存
   * @return
   */
  private boolean clearWhenStale() {
    if (System.currentTimeMillis() - lastClear > clearInterval) {
      clear();
      return true;
    }
    return false;
  }

  @Override
  public String getId() {
    return delegate.getId();
  }

  @Override
  public int getSize() {
    clearWhenStale();
    return delegate.getSize();
  }

  @Override
  public void putObject(Object key, Object object) {
    clearWhenStale();
    delegate.putObject(key, object);
  }

  @Override
  public Object getObject(Object key) {
    return clearWhenStale() ? null : delegate.getObject(key);
  }

  @Override
  public Object removeObject(Object key) {
    clearWhenStale();
    return delegate.removeObject(key);
  }

  @Override
  public void clear() {
    lastClear = System.currentTimeMillis();
    delegate.clear();
  }

  @Override
  public ReadWriteLock getReadWriteLock() {
    return null;
  }

  @Override
  public int hashCode() {
    return delegate.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return delegate.equals(obj);
  }

}
