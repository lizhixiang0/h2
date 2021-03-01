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
package org.apache.ibatis.reflection.wrapper;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.ReflectionException;
import org.apache.ibatis.reflection.property.PropertyTokenizer;

/**
 *  BaseWrapper 是实现 ObjectWrapper 接口的抽象子类，主要为子类 BeanWrapper 和 MapWrapper 提供属性值的获取和设置的功能，
 *  包装了 MetaObject 对象
 * @author Clinton Begin
 */
public abstract class BaseWrapper implements ObjectWrapper {

  /**
   * no arguments ,不知道这种方式有啥好处
   */
  protected static final Object[] NO_ARGUMENTS = new Object[0];

  protected MetaObject metaObject;

  /**
   * 抽象类虽然不能被实例化,但是抽象类可以有构造函数,用来初始化一些属性
   * @param metaObject metaObject
   */
  protected BaseWrapper(MetaObject metaObject) {
    this.metaObject = metaObject;
  }

  /**
   * 解析对象中的集合名，调用 MetaObject 的方法获取对应的属性值返回
   * 普通包装器和Map包装器会调用
   */
  protected Object resolveCollection(PropertyTokenizer prop, Object object) {
    // 如果表达式不合法解析不到属性名，则直接返回默认值
    if ("".equals(prop.getName())) {
      return object;
    } else {
      // 解析到属性名，调用 MetaObject 的方法获取属性值返回
      return metaObject.getValue(prop.getName());
    }
  }

  /**
   * 根据属性表达式，获取对应集合中的属性值返回，这里的集合指 Map、List、Object[] 和基本类型数组。
   */
  protected Object getCollectionValue(PropertyTokenizer prop, Object collection) {
    // 如果集合是一个 Map 对象，则表达式中的索引就代表 Map 中对应的 key，eg: map['key']
    if (collection instanceof Map) {
      return ((Map) collection).get(prop.getIndex());
    } else {
      // 如果集合是一个列表或数组，则下标肯定是一个整数，eg: list[0]/arr[0]
      int i = Integer.parseInt(prop.getIndex());
      if (collection instanceof List) {
        return ((List) collection).get(i);
      } else if (collection instanceof Object[]) {
        return ((Object[]) collection)[i];
      } else if (collection instanceof char[]) {
        return ((char[]) collection)[i];
      } else if (collection instanceof boolean[]) {
        return ((boolean[]) collection)[i];
      } else if (collection instanceof byte[]) {
        return ((byte[]) collection)[i];
      } else if (collection instanceof double[]) {
        return ((double[]) collection)[i];
      } else if (collection instanceof float[]) {
        return ((float[]) collection)[i];
      } else if (collection instanceof int[]) {
        return ((int[]) collection)[i];
      } else if (collection instanceof long[]) {
        return ((long[]) collection)[i];
      } else if (collection instanceof short[]) {
        return ((short[]) collection)[i];
      } else {
        throw new ReflectionException("The '" + prop.getName() + "' property of " + collection + " is not a List or Array.");
      }
    }
  }

  /**
   *  设置集合 || 列表的值
   */
  protected void setCollectionValue(PropertyTokenizer prop, Object collection, Object value) {
    if (collection instanceof Map) {
      ((Map) collection).put(prop.getIndex(), value);
    } else {
      int i = Integer.parseInt(prop.getIndex());
      if (collection instanceof List) {
        ((List) collection).set(i, value);
      } else if (collection instanceof Object[]) {
        ((Object[]) collection)[i] = value;
      } else if (collection instanceof char[]) {
        ((char[]) collection)[i] = (Character) value;
      } else if (collection instanceof boolean[]) {
        ((boolean[]) collection)[i] = (Boolean) value;
      } else if (collection instanceof byte[]) {
        ((byte[]) collection)[i] = (Byte) value;
      } else if (collection instanceof double[]) {
        ((double[]) collection)[i] = (Double) value;
      } else if (collection instanceof float[]) {
        ((float[]) collection)[i] = (Float) value;
      } else if (collection instanceof int[]) {
        ((int[]) collection)[i] = (Integer) value;
      } else if (collection instanceof long[]) {
        ((long[]) collection)[i] = (Long) value;
      } else if (collection instanceof short[]) {
        ((short[]) collection)[i] = (Short) value;
      } else {
        throw new ReflectionException("The '" + prop.getName() + "' property of " + collection + " is not a List or Array.");
      }
    }
  }

}
