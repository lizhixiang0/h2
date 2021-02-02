/*
 * Copyright 2012 MyBatis.org.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ibatis.reflection;

import org.apache.ibatis.reflection.factory.DefaultObjectFactory;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.reflection.wrapper.DefaultObjectWrapperFactory;
import org.apache.ibatis.reflection.wrapper.ObjectWrapperFactory;

/**
 * 一些系统级别的元对象
 * @author Clinton Begin
 */
public final class SystemMetaObject {

  /**
   * 默认对象工厂
   */
  public static final ObjectFactory DEFAULT_OBJECT_FACTORY = new DefaultObjectFactory();
  /**
   * 默认对象包装工厂
   */
  public static final ObjectWrapperFactory DEFAULT_OBJECT_WRAPPER_FACTORY = new DefaultObjectWrapperFactory();

  /**
   * MetaObject的初始对象（originalObject）为null
   */
  public static final MetaObject NULL_META_OBJECT = MetaObject.forObject(NullObject.class, DEFAULT_OBJECT_FACTORY, DEFAULT_OBJECT_WRAPPER_FACTORY);

  /**
   * 构造私有化
   */
  private SystemMetaObject() {}

  /**
   *  可以调用SystemMetaObject.forObject()来创建MetaObject对象
   * @param object obj
   * @return MetaObject
   */
  public static MetaObject forObject(Object object) {
    return MetaObject.forObject(object, DEFAULT_OBJECT_FACTORY, DEFAULT_OBJECT_WRAPPER_FACTORY);
  }

  /**
   * 私有的静态内部类,就是充当null而已
   */
  private static class NullObject {}



}
