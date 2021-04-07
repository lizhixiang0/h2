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
package org.apache.ibatis.builder;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.ibatis.mapping.ParameterMode;
import org.apache.ibatis.mapping.ResultSetType;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeAliasRegistry;
import org.apache.ibatis.type.TypeHandler;
import org.apache.ibatis.type.TypeHandlerRegistry;

/**
 * 构建器的基类,里面定义了一些protected方法
 * @author Clinton Begin
 */
public abstract class BaseBuilder {

  // 核心配置类
  protected final Configuration configuration;
  // 类型别名注册器
  protected final TypeAliasRegistry typeAliasRegistry;
  // 类型处理器注册器
  protected final TypeHandlerRegistry typeHandlerRegistry;

  /**
   * 构造方法
   * @param configuration configuration
   */
  public BaseBuilder(Configuration configuration) {
    this.configuration = configuration;
    this.typeAliasRegistry = this.configuration.getTypeAliasRegistry();
    this.typeHandlerRegistry = this.configuration.getTypeHandlerRegistry();
  }

  /**
   * 将给定的正则表达式编译成Pattern模式
   * @param regex 正则
   * @param defaultValue 默认正则
   */
  protected Pattern parseExpression(String regex, String defaultValue) {
    return Pattern.compile(regex == null ? defaultValue : regex);
  }

  /**
   * 效果类似Optional.of().orElse().get()
   * @param value 给定值(字符类型)
   * @param defaultValue  默认值
   * @return boolean包装类型
   */
  protected Boolean booleanValueOf(String value, Boolean defaultValue) {
    return value == null ? defaultValue : Boolean.valueOf(value);
  }

  /**
   * 效果类似Optional.of().orElse().get()
   * @param value 给定值(字符类型)
   * @param defaultValue 默认值
   * @return Integer包装类型
   */
  protected Integer integerValueOf(String value, Integer defaultValue) {
    return value == null ? defaultValue : Integer.valueOf(value);
  }

  /**
   * 第一步：效果类似Optional.of().orElse().get()
   * 第二步：把以逗号分割的一个字符串重新包装，返回一个Set
   * @param value 给定值(字符类型)
   * @param defaultValue  默认值
   * @return HashSet类型
   */
  protected Set<String> stringSetValueOf(String value, String defaultValue) {
    value = (value == null ? defaultValue : value);
    return new HashSet<>(Arrays.asList(value.split(",")));
  }

  /**
   * 利用JdbcType.valueOf(alias);将string类型转为JdbcType枚举类型
   * @param alias string类型
   * @return JdbcType
   */
  protected JdbcType resolveJdbcType(String alias) {
    if (alias == null) {
      return null;
    }
    try {
      return JdbcType.valueOf(alias);
    } catch (IllegalArgumentException e) {
      throw new BuilderException("Error resolving JdbcType. Cause: " + e, e);
    }
  }

  /**
   * 利用ResultSetType.valueOf(alias);将string类型转为ResultSetType枚举类型
   * @param alias string类型
   * @return ResultSetType
   */
  protected ResultSetType resolveResultSetType(String alias) {
    if (alias == null) {
      return null;
    }
    try {
      return ResultSetType.valueOf(alias);
    } catch (IllegalArgumentException e) {
      throw new BuilderException("Error resolving ResultSetType. Cause: " + e, e);
    }
  }

  /**
   * 利用ParameterMode.valueOf(alias);将string类型转为ParameterMode枚举类型
   * @param alias string类型
   * @return ParameterMode
   */
  protected ParameterMode resolveParameterMode(String alias) {
    if (alias == null) {
      return null;
    }
    try {
      return ParameterMode.valueOf(alias);
    } catch (IllegalArgumentException e) {
      throw new BuilderException("Error resolving ParameterMode. Cause: " + e, e);
    }
  }

  /**
   * 根据别名或全限定名解析Class，然后创建实例
   * @param alias  别名 || 全限定名
   * @return  Object
   */
  protected Object createInstance(String alias) {
    Class<?> clazz = resolveClass(alias);
    if (clazz == null) {
      return null;
    }
    try {
      return resolveClass(alias).newInstance();
    } catch (Exception e) {
      throw new BuilderException("Error creating instance. Cause: " + e, e);
    }
  }

  /**
   * 根据别名或全限定名解析Class
   * @param alias 别名 || 全限定名
   * @return clazz
   */
  protected Class<?> resolveClass(String alias) {
    if (alias == null) {
      return null;
    }
    try {
      return resolveAlias(alias);
    } catch (Exception e) {
      throw new BuilderException("Error resolving class. Cause: " + e, e);
    }
  }

  /**
   * 到类型别名注册表里找clazz
   * @param alias 别名 || 全限定名
   * @return clazz
   */
  protected Class<?> resolveAlias(String alias) {
    return typeAliasRegistry.resolveAlias(alias);
  }

  /**
   * 解析类型处理器
   * @param javaType java类型
   * @param typeHandlerAlias 类型处理器别名
   * @return TypeHandler
   */
  protected TypeHandler<?> resolveTypeHandler(Class<?> javaType, String typeHandlerAlias) {
    // 1、必须提供类型处理器别名,不然直接返回null
    if (typeHandlerAlias == null) {
      return null;
    }
    // 2、根据别名从typeAliasRegistry获取clazz
    Class<?> type = resolveClass(typeHandlerAlias);
    // 3、如果不是TypeHandler的子类,报错
    if (type != null && !TypeHandler.class.isAssignableFrom(type)) {
      throw new BuilderException("Type " + type.getName() + " is not a valid TypeHandler because it does not implement TypeHandler interface");
    }
    // 4、上一步确定是TypeHandler的子类,则这里将clazz强转成TypeHandler类型
    @SuppressWarnings( "unchecked" )
    Class<? extends TypeHandler<?>> typeHandlerType = (Class<? extends TypeHandler<?>>) type;
    // 5、再去调用另一个重载的方法
    return resolveTypeHandler(javaType, typeHandlerType);
  }

  /**
   * 根据javaType和typeHandlerType获取类型处理器
   * @param javaType  java类型
   * @param typeHandlerType    类型处理器
   */
  protected TypeHandler<?> resolveTypeHandler(Class<?> javaType, Class<? extends TypeHandler<?>> typeHandlerType) {
    // 1、没提供类型处理器直接返回null
    if (typeHandlerType == null) {
      return null;
    }
    // 2、提供了就到typeHandlerRegistry查询对应的TypeHandler
    TypeHandler<?> handler = typeHandlerRegistry.getMappingTypeHandler(typeHandlerType);
    if (handler == null) {
      //3、如果没找到，调用typeHandlerRegistry.getInstance来new一个TypeHandler
      handler = typeHandlerRegistry.getInstance(javaType, typeHandlerType);
    }
    // 4、返回
    return handler;
  }

  public Configuration getConfiguration() {
    return configuration;
  }
}
