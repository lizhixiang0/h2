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
package org.apache.ibatis.reflection.factory;

import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.ibatis.reflection.ReflectionException;

/**
 * mybatis提供的简单对象工厂，快速创建对象
 * @author Clinton Begin
 */
public class DefaultObjectFactory implements ObjectFactory, Serializable {

  private static final long serialVersionUID = -8855120656740914948L;

  @Override
  public <T> T create(Class<T> type) {
    return create(type, null, null);
  }

  /**
   * 创建对象就两步，
   *  1、找到对象类型
   *  2、通过反射实例化对象
   */
  @SuppressWarnings("unchecked")
  @Override
  public <T> T create(Class<T> type, List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
    //1.解析集合接口，返回集合常用实现类类型
    Class<?> classToCreate = resolveInterface(type);
    //2.实例化类、类型是可分配的
    return (T) instantiateClass(classToCreate, constructorArgTypes, constructorArgs);
  }

  /**
   * 1、对于常见的集合接口，返回其对应常用的实现类
   *
   * 例如：
   *      如果不是接口最好，返回自己的类型，如果是接口则分情况讨论
   *      list、Collection、Iterable 对应着 ArrayList
   *      Map  对应着 HashMap
   *      Set   对应着 HashSet
   *      SortedSet 对应着 TreeSet
   *
   */
  protected Class<?> resolveInterface(Class<?> type) {
    Class<?> classToCreate;
    if (type == List.class || type == Collection.class || type == Iterable.class) {
      classToCreate = ArrayList.class;
    } else if (type == Map.class) {
      classToCreate = HashMap.class;
    } else if (type == SortedSet.class) {
      classToCreate = TreeSet.class;
    } else if (type == Set.class) {
      classToCreate = HashSet.class;
    } else {
      classToCreate = type;
    }
    return classToCreate;
  }

  /**
   * 2、实例化类
   */
  private <T> T instantiateClass(Class<T> type, List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
    try {
      Constructor<T> constructor;
      //如果没有传入参数类型和参数值，则调用空构造函数，核心Constructor.newInstance
      if (constructorArgTypes == null || constructorArgs == null) {
        constructor = type.getDeclaredConstructor();
        if (!constructor.isAccessible()) {
          constructor.setAccessible(true);
        }
        return constructor.newInstance();
      }
      //如果传入参数类型和参数值，说明是有参构造函数，核心是调用Constructor.newInstance,这里可以看到用的toArray的重载方法.值得学习
      constructor = type.getDeclaredConstructor(constructorArgTypes.toArray(new Class[0]));
      if (!constructor.isAccessible()) {
        constructor.setAccessible(true);
      }
      return constructor.newInstance(constructorArgs.toArray(new Object[0]));
    } catch (Exception e) {
      //将构造参数类型和参数值 拼装起来交给ReflectionException抛出
      StringBuilder argTypes = new StringBuilder();
      if (constructorArgTypes != null) {
        for (Class<?> argType : constructorArgTypes) {
          argTypes.append(argType.getSimpleName());
          argTypes.append(",");
        }
      }
      StringBuilder argValues = new StringBuilder();
      if (constructorArgs != null) {
        for (Object argValue : constructorArgs) {
          argValues.append(argValue);
          argValues.append(",");
        }
      }
      throw new ReflectionException("Error instantiating " + type + " with invalid types (" + argTypes + ") or values (" + argValues + "). Cause: " + e, e);
    }
  }

  @Override
  public <T> boolean isCollection(Class<T> type) {
    //判断是否为Collection集合类型
    return Collection.class.isAssignableFrom(type);
  }

  @Override
  public void setProperties(Properties properties) {}

}
