/*
 *    Copyright 2009-2012 the original author or authors.
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
package org.apache.ibatis.mapping;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.ibatis.cache.Cache;
import org.apache.ibatis.cache.CacheException;
import org.apache.ibatis.cache.decorators.BlockingCache;
import org.apache.ibatis.cache.decorators.LoggingCache;
import org.apache.ibatis.cache.decorators.LruCache;
import org.apache.ibatis.cache.decorators.ScheduledCache;
import org.apache.ibatis.cache.decorators.SerializedCache;
import org.apache.ibatis.cache.decorators.SynchronizedCache;
import org.apache.ibatis.cache.impl.PerpetualCache;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.SystemMetaObject;

/**
 * 缓存构建器
 * @author Clinton Begin
 */
public class CacheBuilder {
  /**
   * Namespace,cache的唯一标识
   */
  private String id;
  private Class<? extends Cache> implementation;
  private List<Class<? extends Cache>> decorators;
  private Integer size;
  private Long clearInterval;
  private boolean readWrite;
  private Properties properties;
  private boolean blocking;

  public CacheBuilder(String id) {
    this.id = id;
    this.decorators = new ArrayList<>();
  }

  public CacheBuilder implementation(Class<? extends Cache> implementation) {
    this.implementation = implementation;
    return this;
  }

  public CacheBuilder addDecorator(Class<? extends Cache> decorator) {
    if (decorator != null) {
      this.decorators.add(decorator);
    }
    return this;
  }

  public CacheBuilder size(Integer size) {
    this.size = size;
    return this;
  }

  public CacheBuilder clearInterval(Long clearInterval) {
    this.clearInterval = clearInterval;
    return this;
  }

  public CacheBuilder readWrite(boolean readWrite) {
    this.readWrite = readWrite;
    return this;
  }

  public CacheBuilder blocking(boolean blocking) {
    this.blocking = blocking;
    return this;
  }

  public CacheBuilder properties(Properties properties) {
    this.properties = properties;
    return this;
  }

  /**
   * 构建cache的核心build方法
   * @return cache
   */
  public Cache build() {
    setDefaultImplementations();
    // 1、创建缓存对象 （这里为啥不用对象工厂？）
    Cache cache = newBaseCacheInstance(implementation, id);
    // 2、设额外属性
    setCacheProperties(cache);
    // 3、判断是不是自定义缓存
    if (PerpetualCache.class.equals(cache.getClass())) {
      // 4、不是自定义缓存,遍历添加装饰器
      for (Class<? extends Cache> decorator : decorators) {
        // a、套上过期缓存装饰器
        cache = newCacheDecoratorInstance(decorator, cache);
        // b、作为额外属性设置进cache
        setCacheProperties(cache);
      }
      // c、再附加上标准的装饰者
      cache = setStandardDecorators(cache);
    } else if (!LoggingCache.class.isAssignableFrom(cache.getClass())) {
      // 5、给自定义缓存需套日志装饰器,与mybatis的cache日志统一
      cache = new LoggingCache(cache);
    }
    return cache;
  }

  /**
   * 判断基础cache和基础装饰cache是否为null ,设置默认值
   * 我们看到默认的就是PerpetualCache和LruCache ！！！这两货一个提供了容器，一个提供了过期策略！！这两个功能对缓存来讲是基本的。
   */
  private void setDefaultImplementations() {
    if (implementation == null) {
      implementation = PerpetualCache.class;
      if (decorators.isEmpty()) {
        decorators.add(LruCache.class);
      }
    }
  }

  /**
   * 设置装饰器，丰富缓存策略
   */
  private Cache setStandardDecorators(Cache cache) {
    try {
      MetaObject metaCache = SystemMetaObject.forObject(cache);
      // 1、假如缓存有size属性,就设置
      if (size != null && metaCache.hasSetter("size")) {
        metaCache.setValue("size", size);
      }
      // 2、假如配置了清理间隔时间,那就套上ScheduledCache装饰器
      if (clearInterval != null) {
        cache = new ScheduledCache(cache);
        ((ScheduledCache) cache).setClearInterval(clearInterval);
      }
      // 3、readWrite默认是false,代表使用者从缓存里取出的对象改变后能被其他使用感知到！（默认是false,因为通常我们改变后会重新插入）
      if (readWrite) {
          //如果readOnly=true,代表不可写,不同的使用者读出的内容始终是一样的！除非重新插入缓存！
        cache = new SerializedCache(cache);
      }
      // 4、日志缓存装饰器是必须的
      cache = new LoggingCache(cache);
      // 5、同步缓存也是必须的
      cache = new SynchronizedCache(cache);
      // 6、如果配置block=true ,则加上阻塞缓存装饰器，能防止缓存击穿
      if (blocking) {
        cache = new BlockingCache(cache);
      }
      return cache;
    } catch (Exception e) {
      throw new CacheException("Error building standard cache decorators.  Cause: " + e, e);
    }
  }

  /**
   * 利用MetaObject给缓存设置额外的property属性 （一般只有自定义的cache可能会有）
   */
  private void setCacheProperties(Cache cache) {
    if (properties != null) {
      // 1、获取cache的元类
      MetaObject metaCache = SystemMetaObject.forObject(cache);
      // 2、遍历properties,给cache设置属性
      for (Map.Entry<Object, Object> entry : properties.entrySet()) {
        String name = (String) entry.getKey();
        String value = (String) entry.getValue();

        // a、判断cache有没有该属性
        if (metaCache.hasSetter(name)) {
          // b、如果有,获取该属性的类型
          Class<?> type = metaCache.getSetterType(name);
          // c、下面就是各种基本类型或包装类型的判断，如果不是基本类型,直接抛异常
          if (String.class == type) {
            metaCache.setValue(name, value);
          } else if (int.class == type
              || Integer.class == type) {
            metaCache.setValue(name, Integer.valueOf(value));
          } else if (long.class == type
              || Long.class == type) {
            metaCache.setValue(name, Long.valueOf(value));
          } else if (short.class == type
              || Short.class == type) {
            metaCache.setValue(name, Short.valueOf(value));
          } else if (byte.class == type
              || Byte.class == type) {
            metaCache.setValue(name, Byte.valueOf(value));
          } else if (float.class == type
              || Float.class == type) {
            metaCache.setValue(name, Float.valueOf(value));
          } else if (boolean.class == type
              || Boolean.class == type) {
            metaCache.setValue(name, Boolean.valueOf(value));
          } else if (double.class == type
              || Double.class == type) {
            metaCache.setValue(name, Double.valueOf(value));
          } else {
            throw new CacheException("Unsupported property type for cache: '" + name + "' of type " + type);
          }
        }
      }
    }
  }

  private Cache newBaseCacheInstance(Class<? extends Cache> cacheClass, String id) {
    Constructor<? extends Cache> cacheConstructor = getBaseCacheConstructor(cacheClass);
    try {
      return cacheConstructor.newInstance(id);
    } catch (Exception e) {
      throw new CacheException("Could not instantiate cache implementation (" + cacheClass + "). Cause: " + e, e);
    }
  }

  private Constructor<? extends Cache> getBaseCacheConstructor(Class<? extends Cache> cacheClass) {
    try {
      return cacheClass.getConstructor(String.class);
    } catch (Exception e) {
      throw new CacheException("Invalid base cache implementation (" + cacheClass + ").  " +
          "Base cache implementations must have a constructor that takes a String id as a parameter.  Cause: " + e, e);
    }
  }

  private Cache newCacheDecoratorInstance(Class<? extends Cache> cacheClass, Cache base) {
    Constructor<? extends Cache> cacheConstructor = getCacheDecoratorConstructor(cacheClass);
    try {
      return cacheConstructor.newInstance(base);
    } catch (Exception e) {
      throw new CacheException("Could not instantiate cache decorator (" + cacheClass + "). Cause: " + e, e);
    }
  }

  private Constructor<? extends Cache> getCacheDecoratorConstructor(Class<? extends Cache> cacheClass) {
    try {
      return cacheClass.getConstructor(Cache.class);
    } catch (Exception e) {
      throw new CacheException("Invalid cache decorator (" + cacheClass + ").  " +
          "Cache decorators must have a constructor that takes a Cache instance as a parameter.  Cause: " + e, e);
    }
  }
}
