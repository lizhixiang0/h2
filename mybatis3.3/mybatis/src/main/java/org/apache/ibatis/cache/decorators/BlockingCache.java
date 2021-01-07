package org.apache.ibatis.cache.decorators;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.ibatis.cache.Cache;
import org.apache.ibatis.cache.CacheException;
import org.apache.ibatis.cache.impl.PerpetualCache;

/**
 * Simple blocking decorator
 *
 * Sipmle and inefficient version of EhCache's BlockingCache decorator.
 * It sets a lock over a cache key when the element is not found in cache.
 * This way, other threads will wait until this element is filled instead of hitting the database.
 * 让缓存拥有阻塞的功能，目的是为了防止缓存击穿。（当在缓存中找不到元素时，它设置对缓存键的锁定，这样，当前线程可以到数据库查询，而其他线程将一直等待，直到该缓存键放入了缓存值）
 * 这个装饰器并不能保证缓存操作的线程安全！！
 * 补充：
 *    某些Key属于极端热点数据，且并发量很大的情况下，如果这个key过期，可能会在某个瞬间出现大量的并发,大量的并发请求直接打到了数据库 。
 *    这种情况，就是我们常说的缓存击穿。
 * @author Eduardo Macarron
 *
 */
public class BlockingCache implements Cache {

  private long timeout;
  private final Cache delegate;
  /**
   * 这里采用分段锁，每一个Key对应一个锁，当在缓存中找不到元素时，它设置当前线程对缓存键的锁定。由当前线程到数据库查询数据
   * 其他线程则一直等待，直到该缓存键放入了缓存值，这也是防止缓存击穿的典型方案。
   *
   * 需要注意的是，这里每一个Key都对应一个锁，就并不能保证对底层Map的更新操作（主要是put操作），
   * 只由一个线程执行，那这样多线程状态下对底层HashMap的更新操作也是线程不安全的！
   *
   * 也就是说，BlockingCache只是为了解决缓存击穿的问题，而不是解决缓存操作的线程安全问题，
   * 线程安全问题交由SynchronizedCache装饰器来完成
   *
   */
  private final ConcurrentHashMap<Object, ReentrantLock> locks;

  public BlockingCache(Cache delegate) {
    this.delegate = delegate;
    this.locks = new ConcurrentHashMap<>();
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
  public void putObject(Object key, Object value) {
    try {
      // 向缓存中添加数据,添加完数据之后，释放锁，这一步源码似乎有点问题，有可能为null
      delegate.putObject(key, value);
    } finally {
      /**
       * 举例说明：假如线程A从数据库中查找到keyA对应的结果对象后，将结果放入到BlockingCache 中，此时线程A会释放keyA对应的锁，唤醒阻塞在该锁上的线程，
       * 其它线程可以从缓存中获取数据，而不是再次访问数据库。
       */
      releaseLock(key);
    }
  }

  @Override
  public Object getObject(Object key) {
    // 获取key对应的锁，如果拿到则执行下一步，拿不到要么无限等待，要么超出指定时间则抛出异常
    acquireLock(key);
    Object value = delegate.getObject(key);
    if (value != null) {
      // 如果从缓存中查找到value值，则释放锁，否则继续持有锁
      releaseLock(key);
    }
    return value;
  }

  @Override
  public Object removeObject(Object key) {
    return delegate.removeObject(key);
  }

  @Override
  public void clear() {
    delegate.clear();
  }

  @Override
  public ReadWriteLock getReadWriteLock() {
    return null;
  }

  private ReentrantLock getLockForKey(Object key) {
    // 创建ReentrantLock对象
    ReentrantLock lock = new ReentrantLock();
    /**
     * 尝试添加到locks集合中，如果locks集合中已经有了相应的Reentrantock对象，则使用原有的locks 中的ReentrantLock对象
     * 补充：put与putIfAbsent区别？
     *      put在放入数据时,如果放入数据的key已经存在与Map中,最后放入的数据会覆盖之前存在的数据,
     *      而putIfAbsent在放入数据时,如果存在重复的key,那么putIfAbsent不会放入值，且会返回之前绑定的值
     **/
    ReentrantLock previous = locks.putIfAbsent(key, lock);
    return previous == null ? lock : previous;
  }

  private void acquireLock(Object key) {
    // 获取ReentrantLock 对象
    Lock lock = getLockForKey(key);
    if (timeout > 0) {
      try {
        //则尝试在指定时间内获取锁，超时仍未获取则抛出异常
        boolean acquired = lock.tryLock(timeout, TimeUnit.MILLISECONDS);
        if (!acquired) {
          throw new CacheException("Couldn't get a lock in " + timeout + " for the key " +  key + " at the cache " + delegate.getId());
        }
      } catch (InterruptedException e) {
        throw new CacheException("Got interrupted while trying to acquire lock for key " + key, e);
      }
    } else {
      //没有设置超时时间，则直接无限期等待锁
      lock.lock();
    }
  }

  private void releaseLock(Object key) {
    ReentrantLock lock = locks.get(key);
    // 锁是否被当前线程持有
    if (Objects.nonNull(lock)&&lock.isHeldByCurrentThread()) {
      // 释放锁
      lock.unlock();
    }
  }

  public long getTimeout() {
    return timeout;
  }

  public void setTimeout(long timeout) {
    this.timeout = timeout;
  }
}
