/*
 *    Copyright 2009-2013 the original author or authors.
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
package org.apache.ibatis.type;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.io.ResolverUtil;
import org.apache.ibatis.io.Resources;

/**
 * 类型注册机
 * @author Clinton Begin
 */
public class TypeAliasRegistry {

  /**
   * 注册器的容器
   * key为我们给类型取的别名,引用类型用类型名（小写）,基本类型在前面加下划线
   * value 则是具体类型
   */
  private final Map<String, Class<?>> TYPE_ALIASES = new HashMap<>();

  /**
   * 构造函数里注册系统内置的类型别名
   */
  public TypeAliasRegistry() {
    registerAlias("string", String.class);
	//基本包装类型
    registerAlias("byte", Byte.class);
    registerAlias("long", Long.class);
    registerAlias("short", Short.class);
    registerAlias("int", Integer.class);
    registerAlias("integer", Integer.class);
    registerAlias("double", Double.class);
    registerAlias("float", Float.class);
    registerAlias("boolean", Boolean.class);
	//基本数组包装类型
    registerAlias("byte[]", Byte[].class);
    registerAlias("long[]", Long[].class);
    registerAlias("short[]", Short[].class);
    registerAlias("int[]", Integer[].class);
    registerAlias("integer[]", Integer[].class);
    registerAlias("double[]", Double[].class);
    registerAlias("float[]", Float[].class);
    registerAlias("boolean[]", Boolean[].class);
	//加个下划线，则是基本类型
    registerAlias("_byte", byte.class);
    registerAlias("_long", long.class);
    registerAlias("_short", short.class);
    registerAlias("_int", int.class);
    registerAlias("_integer", int.class);
    registerAlias("_double", double.class);
    registerAlias("_float", float.class);
    registerAlias("_boolean", boolean.class);
	//加个下划线，就变成了基本数组类型
    registerAlias("_byte[]", byte[].class);
    registerAlias("_long[]", long[].class);
    registerAlias("_short[]", short[].class);
    registerAlias("_int[]", int[].class);
    registerAlias("_integer[]", int[].class);
    registerAlias("_double[]", double[].class);
    registerAlias("_float[]", float[].class);
    registerAlias("_boolean[]", boolean[].class);
	//日期数字型
    registerAlias("date", Date.class);
    registerAlias("decimal", BigDecimal.class);
    registerAlias("bigdecimal", BigDecimal.class);
    registerAlias("biginteger", BigInteger.class);
    registerAlias("object", Object.class);
    registerAlias("date[]", Date[].class);
    registerAlias("decimal[]", BigDecimal[].class);
    registerAlias("bigdecimal[]", BigDecimal[].class);
    registerAlias("biginteger[]", BigInteger[].class);
    registerAlias("object[]", Object[].class);
	//集合型
    registerAlias("map", Map.class);
    registerAlias("hashmap", HashMap.class);
    registerAlias("list", List.class);
    registerAlias("arraylist", ArrayList.class);
    registerAlias("collection", Collection.class);
    registerAlias("iterator", Iterator.class);
	//还有个ResultSet型
    registerAlias("ResultSet", ResultSet.class);
  }


  /**
   * 解析别名返回具体类型 ，比如传递 int ,会返回 Integer.class
   * @param string 可以传递别名 (int ),也可以传递全限定名(java.lang.int)
   * @return clazz
   */
  @SuppressWarnings("unchecked")
  public <T> Class<T> resolveAlias(String string) {
    try {
      if (string == null) {
        return null;
      }
      // 1、先转成小写再解析
      //这里转小写有bug,比如如果本地语言是Turkish，那i转成大写就不是I了，而是另外一个字符（İ）。这样土耳其的机器就用不了mybatis了！这是一个很大的bug，但是基本上每个人都会犯......https://code.google.com/p/mybatis/issues
      String key = string.toLowerCase(Locale.ENGLISH);
      Class<T> value;
      // 2、从HashMap里找对应的键值，找到则返回类型别名对应的Class
      if (TYPE_ALIASES.containsKey(key)) {
        value = (Class<T>) TYPE_ALIASES.get(key);
      } else {
        // 3、找不到,尝试使用Resources.classForName(),如果string是全限定名,那也可以找到，例如 java.lang.Integer
        value = (Class<T>) Resources.classForName(string);
      }
      return value;
    } catch (ClassNotFoundException e) {
      // 4、没找到肯定会抛出异常
      throw new TypeException("Could not resolve type alias '" + string + "'.  Cause: " + e, e);
    }
  }

  /**
   * 扫描并注册某包下所有的类并注册
   * @param packageName 具体的包名
   */
  public void registerAliases(String packageName){
    registerAliases(packageName, Object.class);
  }

  /**
   * 扫描并注册某包下所有继承于superType的类型别名
   * @param packageName 具体的包名
   * @param superType 超类
   */
  public void registerAliases(String packageName, Class<?> superType){
    ResolverUtil<Class<?>> resolverUtil = new ResolverUtil<>();
    resolverUtil.find(new ResolverUtil.IsA(superType), packageName);
    Set<Class<? extends Class<?>>> typeSet = resolverUtil.getClasses();
    for(Class<?> type : typeSet){
      // 忽略匿名类、内部类、接口以及package-info类
      if (!type.isAnonymousClass() && !type.isInterface() && !type.isMemberClass()) {
        registerAlias(type);
      }
    }
  }

  /**
   * 注册类型 这个不提供别名，方法内部使用getSimpleName()获得类名作为别名
   * @param type 某类
   */
  public void registerAlias(Class<?> type) {
    // 1、获得类名作为别名 TypeAliasRegistry.class.getSimpleName() ---> TypeAliasRegistry
    String alias = type.getSimpleName();
	// 2、获得Alias注解 ,没有返回null
    Alias aliasAnnotation = type.getAnnotation(Alias.class);
    if (aliasAnnotation != null) {
      // 2.1、如果有注解则获得其value作为别名
      alias = aliasAnnotation.value();
    }
    // 3、注册类型
    registerAlias(alias, type);
  }

  /**
   * 注册类型 , 这个牛逼一点,自己提供别名
   * @param alias 别名
   * @param value 某类
   */
  public void registerAlias(String alias, Class<?> value) {
    // 1、校验别名是否为空
    if (alias == null) {
      throw new TypeException("The parameter alias cannot be null");
    }
    // 2、别名转小写
    String key = alias.toLowerCase(Locale.ENGLISH);

    // 3、如果已经存在key了，且value和之前不一致，报错 （意思是如果key一样,value也一样就不报错,确实没必要报错）
    if (TYPE_ALIASES.containsKey(key) && TYPE_ALIASES.get(key) != null && !TYPE_ALIASES.get(key).equals(value)) {
      throw new TypeException("The alias '" + alias + "' is already mapped to the value '" + TYPE_ALIASES.get(key).getName() + "'.");
    }
    // 4、满足一些条件了,开始put,HashMap的put逻辑是存在key一样的就覆盖
    TYPE_ALIASES.put(key, value);
  }

  /**
   * 注册类型 , 这个更牛逼一点,直接提供全限定名
   * @param alias 别名
   * @param value 某类的全限定名
   */
  public void registerAlias(String alias, String value) {
    try {
      registerAlias(alias, Resources.classForName(value));
    } catch (ClassNotFoundException e) {
      throw new TypeException("Error registering type alias "+alias+" for "+value+". Cause: " + e, e);
    }
  }

  /**
   * 获得类型注册器,值得注意的是这个方法拿到的是不可变类型
   */
  public Map<String, Class<?>> getTypeAliases() {
    return Collections.unmodifiableMap(TYPE_ALIASES);
  }

}
