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
package org.apache.ibatis.cache;

import java.io.Serializable;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;

/**
 *  缓存key
 *  一般缓存框架的数据结构基本上都是 Key-Value 方式存储,事实上mybatis就是存储在hashMap中
 *  MyBatis 对于其 Key 的生成采取规则为：[mappedStatementId + offset + limit + SQL + queryParams + environment]生成一个哈希码
 * @author Clinton Begin
 * @blog "https://blog.csdn.net/xl3379307903/article/details/80517841
 */
public class CacheKey implements Cloneable, Serializable {

  private static final long serialVersionUID = 1146682552656046210L;

  public static final CacheKey NULL_CACHE_KEY = new NullCacheKey();

  private static final int DEFAULT_MULTIPLIER = 37;

  private static final int DEFAULT_HASHCODE = 17;

  /**
   * 参与计算hashcode,默认值是37
   */
  private int multiplier;
  /**
   * CacheKey的hashcode,初始值是17
   */
  private int hashcode;
  /**
   * 校验和
   */
  private long checksum;

  private int count;
  /**
   * 该集合中的所有对象决定两个CacheKey是否相同
   */
  private List<Object> updateList;

  public CacheKey() {
    this.hashcode = DEFAULT_HASHCODE;
    this.multiplier = DEFAULT_MULTIPLIER;
    this.count = 0;
    this.updateList = new ArrayList<>();
  }

  /**
   * 传入一个Object数组，更新hashcode和效验码
   * @param objects
   */
  public CacheKey(Object[] objects) {
    this();
    updateAll(objects);
  }

  public void updateAll(Object[] objects) {
    for (Object o : objects) {
      update(o);
    }
  }

  public void update(Object object) {
    if (object != null && object.getClass().isArray()) {
        //如果是数组，则循环调用doUpdate
      int length = Array.getLength(object);
      for (int i = 0; i < length; i++) {
        Object element = Array.get(object, i);
        doUpdate(element);
      }
    } else {
        //否则，doUpdate
      doUpdate(object);
    }
  }

  /**
   * 重新计算count、checksum、hashcode，并把object对象添加到updateList集合中
   * @param object
   */
  private void doUpdate(Object object) {
    //计算hash值、校验码、count
    int baseHashCode = object == null ? 1 : object.hashCode();
    count++;
    checksum += baseHashCode;
    baseHashCode *= count;
    /**
     * 如何生产hashcode
     * 17是质子数中一个“不大不小”的存在，如果你使用的是一个如2的较小质数，
     * 那么得出的乘积会在一个很小的范围，很容易造成哈希值的冲突。
     * 而如果选择一个100以上的质数，得出的哈希值会超出int的最大范围，这两种都不合适。
     * 而如果对超过 50,000 个英文单词（由两个不同版本的 Unix 字典合并而成）进行 hash code 运算，
     * 并使用常数 31, 33, 37, 39 和 41 作为乘子（cachekey使用37），每个常数算出的哈希值冲突数都小于7个（国外大神做的测试），
     * 那么这几个数就被作为生成hashCode值得备选乘数了
     */
    hashcode = multiplier * hashcode + baseHashCode;

    //同时将对象加入列表，这样万一两个CacheKey的hash码碰巧一样，再根据对象严格equals来区分
    updateList.add(object);
  }

  public int getUpdateCount() {
    return updateList.size();
  }

  @Override
  public boolean equals(Object object) {
    if (this == object) {
      return true;
    }
    if (!(object instanceof CacheKey)) {
      return false;
    }

    final CacheKey cacheKey = (CacheKey) object;

    //先比hashcode，checksum，count，理论上可以快速比出来
    if (hashcode != cacheKey.hashcode) {
      return false;
    }
    if (checksum != cacheKey.checksum) {
      return false;
    }
    if (count != cacheKey.count) {
      return false;
    }

    //万一两个CacheKey的hash码碰巧一样，再根据对象严格equals来区分
    //这里两个list的size没比是否相等，其实前面count相等就已经保证了
    for (int i = 0; i < updateList.size(); i++) {
      Object thisObject = updateList.get(i);
      Object thatObject = cacheKey.updateList.get(i);
      if (thisObject == null) {
        if (thatObject != null) {
          return false;
        }
      } else {
        if (!thisObject.equals(thatObject)) {
          return false;
        }
      }
    }
    return true;
  }

  @Override
  public int hashCode() {
    return hashcode;
  }

  @Override
  public String toString() {
    StringBuilder returnValue = new StringBuilder().append(hashcode).append(':').append(checksum);
    for (int i = 0; i < updateList.size(); i++) {
      returnValue.append(':').append(updateList.get(i));
    }

    return returnValue.toString();
  }

  @Override
  public CacheKey clone() throws CloneNotSupportedException {
    /**
     * 原型模式l,通过clone()来创建一个新的CacheKey对象,需要注意的是引用类型要重新赋值
     */
    CacheKey clonedCacheKey = (CacheKey) super.clone();
    clonedCacheKey.updateList = new ArrayList<Object>(updateList);
    return clonedCacheKey;
  }

}
