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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.ibatis.cache.Cache;
import org.apache.ibatis.cache.CacheException;
import org.apache.ibatis.io.Resources;

/**
 * 序列化缓存,用途是先将对象序列化成2进制，再缓存,好处是将对象压缩了，省内存，坏处是速度慢了
 * @author Clinton Begin
 */
public class SerializedCache implements Cache {

  private Cache delegate;

  public SerializedCache(Cache delegate) {
    this.delegate = delegate;
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
    if (object == null || object instanceof Serializable) {
      /**
       * 先序列化，再putObject
       */
      delegate.putObject(key, serialize((Serializable) object));
    } else {
      throw new CacheException("SharedCache failed to make a copy of a non-serializable object: " + object);
    }
  }

  @Override
  public Object getObject(Object key) {
    /**
     * 取出后反序列化
     */
    Object object = delegate.getObject(key);
    return object == null ? null : deserialize((byte[]) object);
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

  @Override
  public int hashCode() {
    return delegate.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return delegate.equals(obj);
  }


  /**
   * 序列化核心就是ByteArrayOutputStream
   * @param value
   * @return
   */
  private byte[] serialize(Serializable value) {
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
         ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(value);
      oos.flush();
      return bos.toByteArray();
    } catch (Exception e) {
      throw new CacheException("Error serializing object.  Cause: " + e, e);
    }
  }

  /**
   * 反序列化核心就是ByteArrayInputStream
   * @param value
   * @return
   */
  private Serializable deserialize(byte[] value) {
    Serializable result;
    try (ByteArrayInputStream bis = new ByteArrayInputStream(value);
         ObjectInputStream ois = new CustomObjectInputStream(bis)) {
      result = (Serializable) ois.readObject();
    } catch (Exception e) {
      throw new CacheException("Error deserialize object.  Cause: " + e, e);
    }
    return result;
  }

  /**
   * 这里为什么要定制化ObjectInputStream？
   */
  public static class CustomObjectInputStream extends ObjectInputStream {

    public CustomObjectInputStream(InputStream in) throws IOException {
      super(in);
    }


    /**
     * Subclasses may implement this method to allow classes to be fetched from an alternate source
     * 加载与指定的流类描述等效的本地类。 子类可以实现此方法，以允许从备用源中获取类
     * @param desc
     * @return
     * @throws ClassNotFoundException
     */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws ClassNotFoundException {
      /**
       *
       * 改写了ObjectInputStream的resolveClass方法,使用mybatis自己的资源加载器去加载类
       */
      return Resources.classForName(desc.getName());
    }

  }

}
