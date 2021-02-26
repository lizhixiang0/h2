/*
 *    Copyright 2009-2011 the original author or authors.
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
package org.apache.ibatis.reflection;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collection;

import org.apache.ibatis.reflection.invoker.GetFieldInvoker;
import org.apache.ibatis.reflection.invoker.Invoker;
import org.apache.ibatis.reflection.invoker.MethodInvoker;
import org.apache.ibatis.reflection.property.PropertyTokenizer;

/**
 * MetaClass 通过对 Reflector 和 PropertyTokenizer 组合使用，实现了对复杂的属性表达式的解析
 * 可以看到方法基本都是委派给了Reflector
 * @author Clinton Begin
 */
public class MetaClass {

  private Reflector reflector;

  /**
   * 构造私有化
   * @param type
   */
  private MetaClass(Class<?> type) {
    this.reflector = Reflector.forClass(type);
  }

  public static MetaClass forClass(Class<?> type) {
    return new MetaClass(type);
  }

  public static boolean isClassCacheEnabled() {
    return Reflector.isClassCacheEnabled();
  }

  public static void setClassCacheEnabled(boolean classCacheEnabled) {
    Reflector.setClassCacheEnabled(classCacheEnabled);
  }

  public MetaClass metaClassForProperty(String name) {
    // 根据属性名获得属性类型
    Class<?> propType = reflector.getGetterType(name);
    // 根据指定的类属性名创建对应的MataClass对象。
    return MetaClass.forClass(propType);
  }

  /**
   * 根据字符串查找属性名，如果查不到返回null
   * @param name person.school.address
   * @return person.school.address
   */
  public String findProperty(String name) {
    // 这里为什么要提前构造一个builder扔进去，因为buildProperty可能是个递归调用,我们要得到的是递归几轮后的那个值
    StringBuilder prop = buildProperty(name, new StringBuilder());
    return prop.length() > 0 ? prop.toString() : null;
  }

  /**
   * 递归处理属性表达式，并将处理结果返回给 #findProperty() 方法。
   * 例如 Person类中有个School属性,School有属性address
   * @param name  person.school.address
   * @param builder  person.school.address
   * @return
   */
  private StringBuilder buildProperty(String name, StringBuilder builder) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    if (prop.hasNext()) {
      String propertyName = reflector.findPropertyName(prop.getName());
      if (propertyName != null) {
        builder.append(propertyName);
        builder.append(".");
        MetaClass metaProp = metaClassForProperty(propertyName);
        metaProp.buildProperty(prop.getChildren(), builder);
      }
    } else {
      String propertyName = reflector.findPropertyName(name);
      if (propertyName != null) {
        builder.append(propertyName);
      }
    }
    return builder;
  }


  /**
   * 将user_name转化成username,且因为reflector里面存储的是USERNAME:userName数据格式，所以这里不需要进行驼峰处理，直接把'_'去掉即可
   * @param name
   * @param useCamelCaseMapping
   * @return
   */
  public String findProperty(String name, boolean useCamelCaseMapping) {
    if (useCamelCaseMapping) {
      name = name.replace("_", "");
    }
    return findProperty(name);
  }

  public String[] getGetterNames() {
    return reflector.getGetablePropertyNames();
  }

  public String[] getSetterNames() {
    return reflector.getSetablePropertyNames();
  }

  /*
  * 这个方法麻烦在给定的不一定是 person  ,可能是person.name
   */
  public Class<?> getSetterType(String name) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    if (prop.hasNext()) {
      MetaClass metaProp = metaClassForProperty(prop.getName());
      return metaProp.getSetterType(prop.getChildren());
    } else {
      return reflector.getSetterType(prop.getName());
    }
  }

  /**
   *
   * @param name  richList[0]
   * @return
   */
  public Class<?> getGetterType(String name) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    if (prop.hasNext()) {
      MetaClass metaProp = metaClassForProperty(prop);
      return metaProp.getGetterType(prop.getChildren());
    }
    // issue #506. Resolve the type inside a Collection Object
    return getGetterType(prop);
  }

  private MetaClass metaClassForProperty(PropertyTokenizer prop) {
    Class<?> propType = getGetterType(prop);
    return MetaClass.forClass(propType);
  }

  private Class<?> getGetterType(PropertyTokenizer prop) {
    Class<?> type = reflector.getGetterType(prop.getName());
    //判断类型是不是Collection的子类或者子接口
    if (prop.getIndex() != null && Collection.class.isAssignableFrom(type)) {
      // 现在returnType是个Collection类型，例如ArrayList<String> 或者 直接就是 List
      Type returnType = getGenericGetterType(prop.getName());
      // 判断是不是参数化类型,例如ArrayList<String> ,这个用来获取泛型类型，例如ArrayList<String> 的泛型类型是 String
      if (returnType instanceof ParameterizedType) {
        Type[] actualTypeArguments = ((ParameterizedType) returnType).getActualTypeArguments();
        // 再验证一次，Collection类型即使存在泛型也只有一个
        if (actualTypeArguments != null && actualTypeArguments.length == 1) {
          returnType = actualTypeArguments[0];
          if (returnType instanceof Class) {
            // 如果泛型是个普通类型就直接转化成class返回
            type = (Class<?>) returnType;
          } else if (returnType instanceof ParameterizedType) {
            // 如果泛型还是参数化类型，那就转化成参数化类型返回
            type = (Class<?>) ((ParameterizedType) returnType).getRawType();
          }
        }
      }
    }
    return type;
  }

  /**
   * 属性有的GetInvoker类有两种可能,MethodInvoker和GetFieldInvoker  ,需要分开讨论
   * @param propertyName
   * @return
   */
  private Type getGenericGetterType(String propertyName) {
    try {
      Invoker invoker = reflector.getGetInvoker(propertyName);
      if (invoker instanceof MethodInvoker) {
        Field _method = MethodInvoker.class.getDeclaredField("method");
        _method.setAccessible(true);
        Method method = (Method) _method.get(invoker);
        return method.getGenericReturnType();
      } else if (invoker instanceof GetFieldInvoker) {
        Field _field = GetFieldInvoker.class.getDeclaredField("field");
        _field.setAccessible(true);
        Field field = (Field) _field.get(invoker);
        return field.getGenericType();
      }
    } catch (NoSuchFieldException | IllegalAccessException ignored) {
    }
    return null;
  }

  /**
   * 这个方法麻烦在给定的不一定是 person  ,可能是person.name
   * @param name
   * @return
   */
  public boolean hasSetter(String name) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    if (prop.hasNext()) {
      if (reflector.hasSetter(prop.getName())) {
        MetaClass metaProp = metaClassForProperty(prop.getName());
        return metaProp.hasSetter(prop.getChildren());
      } else {
        return false;
      }
    } else {
      return reflector.hasSetter(prop.getName());
    }
  }

  /**
   * 这个方法麻烦在给定的不一定是 person  ,可能是person.name
   * @param name
   * @return
   */
  public boolean hasGetter(String name) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    if (prop.hasNext()) {
      if (reflector.hasGetter(prop.getName())) {
        MetaClass metaProp = metaClassForProperty(prop);
        return metaProp.hasGetter(prop.getChildren());
      } else {
        return false;
      }
    } else {
      return reflector.hasGetter(prop.getName());
    }
  }

  public Invoker getGetInvoker(String name) {
    return reflector.getGetInvoker(name);
  }

  public Invoker getSetInvoker(String name) {
    return reflector.getSetInvoker(name);
  }

  public boolean hasDefaultConstructor() {
    return reflector.hasDefaultConstructor();
  }

}
