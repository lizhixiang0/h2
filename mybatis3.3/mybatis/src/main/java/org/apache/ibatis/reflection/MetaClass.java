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
    // 1、根据属性名获得属性类型
    Class<?> propType = reflector.getGetterType(name);
    // 2、为类的属性创建对应的MataClass对象。
    return MetaClass.forClass(propType);
  }

  private MetaClass metaClassForProperty(PropertyTokenizer prop) {
    Class<?> propType = getGetterType(prop);
    return MetaClass.forClass(propType);
  }

  /**
   * 根据字符串查找属性名，如果查不到返回null
   * @param name person.school.address
   * @return person.school.address
   */
  public String findProperty(String name) {
    //将表达式委托给 #buildProperty 方法处理，buildProperty递归调用,提前传递了个StringBuilder引用
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
    // (1) 判断是否有子表达式
    if (prop.hasNext()) {
      // (1.1) 查找 PropertyTokenizer.name 对应的属性
      String propertyName = reflector.findPropertyName(prop.getName());
      if (propertyName != null) {
        // 追加属性
        builder.append(propertyName);
        builder.append(".");
        // (1.2) 为该属性创建对应的MetaClass对象
        MetaClass metaProp = metaClassForProperty(propertyName);
        // (1.3) 递归解析 PropertyTokenizer.children 字段，并将解析结果添加到 builder 中保存
        metaProp.buildProperty(prop.getChildren(), builder);
      }
     // (2) 递归出口
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

  public Class<?> getSetterType(String name) {
    // 解析属性表达式
    PropertyTokenizer prop = new PropertyTokenizer(name);
    // 判断是否存在待处理的子表达式
    if (prop.hasNext()) {
      // 获取顶层属性对应的 MetaClass 对象，递归调用
      MetaClass metaProp = metaClassForProperty(prop.getName());
      return metaProp.getSetterType(prop.getChildren());
    } else {
      // 不存在子表达式，直接根据属性名从 reflector 中获取属性 setter 类型
      return reflector.getSetterType(prop.getName());
    }
  }

  /**
   * public class RichType {
   *
   *   private RichType richType;
   *
   *   private String richField;
   *
   *   private String richProperty;
   *
   *   private Map richMap = new HashMap();
   *
   *   private List richList = new ArrayList()
   *
   *   private List<RichType> richList1 = new ArrayList()
   *
   *  }
   *
   *  注意:
   *       meta.getGetterType("richType.richList[0]") == String.class
   * @param name  richList[0]
   * @return
   */
  public Class<?> getGetterType(String name) {
    // 解析属性表达式
    PropertyTokenizer prop = new PropertyTokenizer(name);
    // 判断是否存子表达式children,最终目的是找到最右边的name类型，比如richType.richList[0]，目的是找到[0]的类型
    if (prop.hasNext()) {
      // 获取顶层属性对应的 MetaClass 对象，递归调用  todo 有一个疑点，为什么获取set类型只需要传递属性名？
      MetaClass metaProp = metaClassForProperty(prop);
      return metaProp.getGetterType(prop.getChildren());
    }
    return getGetterType(prop);
  }

  private Class<?> getGetterType(PropertyTokenizer prop) {
    Class<?> type = reflector.getGetterType(prop.getName());
    if (prop.getIndex() != null && Collection.class.isAssignableFrom(type)) {
      // 如果表达式中使用了下标，并且顶层属性的是 Collection 的子类,那需要考虑泛型
      Type returnType = getGenericGetterType(prop.getName());
      // 判断是不是类似ArrayList<String> 的参数化类型,然后获取泛型类型，例如ArrayList<String> 的泛型类型是 String
      if (returnType instanceof ParameterizedType) {
        Type[] actualTypeArguments = ((ParameterizedType) returnType).getActualTypeArguments();
        // Collection类型既使存在泛型也应该只有一个
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
    // 如果没使用下标，或者解析完毕，返回对应的类型
    return type;
  }

  /**
   * 获取属性名对应的类似ArrayList<String> 的参数化类型
   * 通过 method.getGenericReturnType()或 field.getGenericType()
   * 属性有的GetInvoker类有两种可能,MethodInvoker和GetFieldInvoker  ,需要分开讨论
   * @param propertyName
   * @return
   */
  private Type getGenericGetterType(String propertyName) {
    try {
      // 获取属性对应的 getInvoker
      Invoker invoker = reflector.getGetInvoker(propertyName);
      if (invoker instanceof MethodInvoker) {
        Field method = MethodInvoker.class.getDeclaredField("method");
        method.setAccessible(true);
        Method method_ = (Method) method.get(invoker);
        return method_.getGenericReturnType();
      } else if (invoker instanceof GetFieldInvoker) {
        Field field = GetFieldInvoker.class.getDeclaredField("field");
        field.setAccessible(true);
        Field field_ = (Field) field.get(invoker);
        return field_.getGenericType();
      }
    } catch (NoSuchFieldException | IllegalAccessException ignored) {
    }
    return null;
  }

  public boolean hasSetter(String name) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    //若是person.name，需要递归处理
    if (prop.hasNext()) {
      if (reflector.hasSetter(prop.getName())) {
        MetaClass metaProp = metaClassForProperty(prop.getName());
        return metaProp.hasSetter(prop.getChildren());
      } else {
        return false;
      }
    } else {
      // 递归出口
      return reflector.hasSetter(prop.getName());
    }
  }

  public boolean hasGetter(String name) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    //若是person.name，需要递归处理
    if (prop.hasNext()) {
      if (reflector.hasGetter(prop.getName())) {
        MetaClass metaProp = metaClassForProperty(prop);
        return metaProp.hasGetter(prop.getChildren());
      } else {
        return false;
      }
    } else {
      // 递归出口
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
