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

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.io.ResolverUtil;

/**
 * 类型处理器注册表
 * 提前把类型转换时需要用到的各种处理器放进去，需要使用的时候从里面拿。
 * @author Clinton Begin
 */
public final class TypeHandlerRegistry {

  /**
   * 记录JdbcType和TypeHandler之间的对应关系，其中JdbcType是一个枚举类型，它定义对应的JDBC类型
   * 该集合主要用于从结果集读取数据时，将数据从Jdbc类型转换成Java类型
   */
  private final Map<JdbcType, TypeHandler<?>> JDBC_TYPE_HANDLER_MAP = new EnumMap<>(JdbcType.class);

  /**
   * 记录了Java类型向指定的JdbcType转换时，需要使用的TypeHandler对象。
   * 例如：Java类型中的String可能转换成数据库的char、varchar等多种类型，所以存在一对多的关系，所以值要用Map来存储
   */
  private final Map<Type, Map<JdbcType, TypeHandler<?>>> TYPE_HANDLER_MAP = new HashMap<>();

  /**
   * 工厂方法,记录了全部TypeHandler的类型以及该类型相应的TypeHandler实例对象
   */
  private final Map<Class<?>, TypeHandler<?>> ALL_TYPE_HANDLERS_MAP = new HashMap<>();

  /**
   * 未知类型对象的TypeHandler
   */
  private final TypeHandler<Object> UNKNOWN_TYPE_HANDLER = new UnknownTypeHandler(this);

  public TypeHandlerRegistry() {
    //构造函数里注册系统内置的类型处理器
    register(Boolean.class, new BooleanTypeHandler());
    register(boolean.class, new BooleanTypeHandler());
    register(JdbcType.BOOLEAN, new BooleanTypeHandler());
    register(JdbcType.BIT, new BooleanTypeHandler());

    register(Byte.class, new ByteTypeHandler());
    register(byte.class, new ByteTypeHandler());
    register(JdbcType.TINYINT, new ByteTypeHandler());

    register(Short.class, new ShortTypeHandler());
    register(short.class, new ShortTypeHandler());
    register(JdbcType.SMALLINT, new ShortTypeHandler());

    register(Integer.class, new IntegerTypeHandler());
    register(int.class, new IntegerTypeHandler());
    register(JdbcType.INTEGER, new IntegerTypeHandler());

    register(Long.class, new LongTypeHandler());
    register(long.class, new LongTypeHandler());

    register(Float.class, new FloatTypeHandler());
    register(float.class, new FloatTypeHandler());
    register(JdbcType.FLOAT, new FloatTypeHandler());

    register(Double.class, new DoubleTypeHandler());
    register(double.class, new DoubleTypeHandler());
    register(JdbcType.DOUBLE, new DoubleTypeHandler());

	  //以下是为同一个类型的多种变种注册到多个不同的handler
    register(String.class, new StringTypeHandler());
    register(String.class, JdbcType.CHAR, new StringTypeHandler());
    register(String.class, JdbcType.CLOB, new ClobTypeHandler());
    register(String.class, JdbcType.VARCHAR, new StringTypeHandler());
    register(String.class, JdbcType.LONGVARCHAR, new ClobTypeHandler());
    register(String.class, JdbcType.NVARCHAR, new NStringTypeHandler());
    register(String.class, JdbcType.NCHAR, new NStringTypeHandler());
    register(String.class, JdbcType.NCLOB, new NClobTypeHandler());
    register(JdbcType.CHAR, new StringTypeHandler());
    register(JdbcType.VARCHAR, new StringTypeHandler());
    register(JdbcType.CLOB, new ClobTypeHandler());
    register(JdbcType.LONGVARCHAR, new ClobTypeHandler());
    register(JdbcType.NVARCHAR, new NStringTypeHandler());
    register(JdbcType.NCHAR, new NStringTypeHandler());
    register(JdbcType.NCLOB, new NClobTypeHandler());

    register(Object.class, JdbcType.ARRAY, new ArrayTypeHandler());
    register(JdbcType.ARRAY, new ArrayTypeHandler());

    register(BigInteger.class, new BigIntegerTypeHandler());
    register(JdbcType.BIGINT, new LongTypeHandler());

    register(BigDecimal.class, new BigDecimalTypeHandler());
    register(JdbcType.REAL, new BigDecimalTypeHandler());
    register(JdbcType.DECIMAL, new BigDecimalTypeHandler());
    register(JdbcType.NUMERIC, new BigDecimalTypeHandler());

    register(Byte[].class, new ByteObjectArrayTypeHandler());
    register(Byte[].class, JdbcType.BLOB, new BlobByteObjectArrayTypeHandler());
    register(Byte[].class, JdbcType.LONGVARBINARY, new BlobByteObjectArrayTypeHandler());
    register(byte[].class, new ByteArrayTypeHandler());
    register(byte[].class, JdbcType.BLOB, new BlobTypeHandler());
    register(byte[].class, JdbcType.LONGVARBINARY, new BlobTypeHandler());
    register(JdbcType.LONGVARBINARY, new BlobTypeHandler());
    register(JdbcType.BLOB, new BlobTypeHandler());

    register(Object.class, UNKNOWN_TYPE_HANDLER);
    register(Object.class, JdbcType.OTHER, UNKNOWN_TYPE_HANDLER);
    register(JdbcType.OTHER, UNKNOWN_TYPE_HANDLER);

    register(Date.class, new DateTypeHandler());
    register(Date.class, JdbcType.DATE, new DateOnlyTypeHandler());
    register(Date.class, JdbcType.TIME, new TimeOnlyTypeHandler());
    register(JdbcType.TIMESTAMP, new DateTypeHandler());
    register(JdbcType.DATE, new DateOnlyTypeHandler());
    register(JdbcType.TIME, new TimeOnlyTypeHandler());

    register(java.sql.Date.class, new SqlDateTypeHandler());
    register(java.sql.Time.class, new SqlTimeTypeHandler());
    register(java.sql.Timestamp.class, new SqlTimestampTypeHandler());

    // issue #273
    register(Character.class, new CharacterTypeHandler());
    register(char.class, new CharacterTypeHandler());
  }

  public static void main(String[] args) {
    TypeHandlerRegistry typeHandlerRegistry = new TypeHandlerRegistry();
    typeHandlerRegistry.getTypeHandler(Date.class,null);
  }

  /**
   * 判断是否有某java类型对应的处理器
   * @param javaType 某java类型
   * @return true or false
   */
  public boolean hasTypeHandler(Class<?> javaType) {
    return hasTypeHandler(javaType, null);
  }

  /**
   * 判断是否有某java类型和jdbc类型对应的类型处理器,这是个核心方法
   * @param javaType java类型
   * @param jdbcType jdbc类型
   * @return true or false
   */
  public boolean hasTypeHandler(Class<?> javaType, JdbcType jdbcType) {
    return javaType != null && getTypeHandler((Type) javaType, jdbcType) != null;
  }

  public <T> TypeHandler<T> getTypeHandler(Class<T> type) {
    return getTypeHandler((Type) type, null);
  }

  public <T> TypeHandler<T> getTypeHandler(Class<T> type, JdbcType jdbcType) {
    return getTypeHandler((Type) type, jdbcType);
  }

  /**
   * 找到某java类型对应的处理器
   * @param type java类型 这个是不能为null的。
   * @param jdbcType JDBC类型 这个无所谓，如果是null ,那就返回一个StringTypeHandler
   * @return 类型处理器
   */
  @SuppressWarnings("unchecked")
  private <T> TypeHandler<T> getTypeHandler(Type type, JdbcType jdbcType) {
    // 1、从TYPE_HANDLER_MAP获取java类型对应的JDBC处理器集合
    Map<JdbcType, TypeHandler<?>> jdbcHandlerMap = TYPE_HANDLER_MAP.get(type);
    TypeHandler<?> handler = null;
    // 2、如果jdbcHandlerMap不为null,尝试从该JDBC处理器集合中获取该jdbcType对应的TypeHandler
    if (jdbcHandlerMap != null) {
      handler = jdbcHandlerMap.get(jdbcType);
      // 2.1、找不到TypeHandler,就传递null过去，再找一下(一般注册的时候不指定jdbcType,就为null)
      if (handler == null) {
        handler = jdbcHandlerMap.get(null);
      }
    }
    // 3、如果jdbcHandlerMap为null且该java类型不为null、且该java类型不是泛型类、且给java类型是枚举类
    if (handler == null && type != null && type instanceof Class && Enum.class.isAssignableFrom((Class<?>) type)) {
      // 3.1、构建一个枚举类处理器
      handler = new EnumTypeHandler((Class<?>) type);
    }
    // 4、返回处理器
    return (TypeHandler<T>) handler;
  }

  /**
   * 判断是否有某TypeReference对应的类型处理器，TypeReference里面有个rawType属性表示的就是java类型，所以这个方法相当与上面的重载
   * @param javaTypeReference  TypeReference
   * @return true or false
   */
  public boolean hasTypeHandler(TypeReference<?> javaTypeReference) {
    return hasTypeHandler(javaTypeReference, null);
  }

  public <T> TypeHandler<T> getTypeHandler(TypeReference<T> javaTypeReference) {
    return getTypeHandler(javaTypeReference, null);
  }

  public boolean hasTypeHandler(TypeReference<?> javaTypeReference, JdbcType jdbcType) {
    return javaTypeReference != null && getTypeHandler(javaTypeReference, jdbcType) != null;
  }

  public <T> TypeHandler<T> getTypeHandler(TypeReference<T> javaTypeReference, JdbcType jdbcType) {
    return getTypeHandler(javaTypeReference.getRawType(), jdbcType);
  }


  /**
   * 获得某处理器的实例对象
   * @param handlerType clazz
   * @return 处理器实例对象
   */
  public TypeHandler<?> getMappingTypeHandler(Class<? extends TypeHandler<?>> handlerType) {
    return ALL_TYPE_HANDLERS_MAP.get(handlerType);
  }

  /**
   * 获得某处理器的实例对象
   * @param jdbcType jdbcType
   * @return 处理器实例对象
   */
  public TypeHandler<?> getTypeHandler(JdbcType jdbcType) {
    return JDBC_TYPE_HANDLER_MAP.get(jdbcType);
  }

  /**
   * 获得为止类型的处理器的实例对象,代表null
   * @return 处理器实例对象
   */
  public TypeHandler<Object> getUnknownTypeHandler() {
    return UNKNOWN_TYPE_HANDLER;
  }
  // ================================================================
  // 上面是获取处理器实例或判断是否存在，下面是注册,我个人觉得注册应该写上面
  // ================================================================

  /**
   * jdbc type + handler
   * @param jdbcType jdbc类型
   * @param handler 处理器
   */
  public void register(JdbcType jdbcType, TypeHandler<?> handler) {
    JDBC_TYPE_HANDLER_MAP.put(jdbcType, handler);
  }

  /**
   * java type + handler
   * @param javaType java类型
   * @param typeHandler 处理器
   */
  public <T> void register(Class<T> javaType, TypeHandler<? extends T> typeHandler) {
    register((Type) javaType, typeHandler);
  }

  /**
   * java type + handler
   * @param javaType java类型
   * @param typeHandler 处理器
   */
  private <T> void register(Type javaType, TypeHandler<? extends T> typeHandler) {
	// 1、获取@MappedJdbcTypes注解,例如@MappedJdbcTypes({ JdbcType.OTHER }),如果不使用该注解，在mybatis-config.xml中注册该typeHandler的时候需要写明jdbcType="OTHER"
    MappedJdbcTypes mappedJdbcTypes = typeHandler.getClass().getAnnotation(MappedJdbcTypes.class);
    if (mappedJdbcTypes != null) {
      for (JdbcType handledJdbcType : mappedJdbcTypes.value()) {
        // 1.1 如果在类中加了该注解,获得JDBC类型,再进行注册
        register(javaType, handledJdbcType, typeHandler);
      }
      // 1.2 如果该注解中写明了includeNullJdbcType=true,说明没JDBC类型也无所谓，再注册一次，此时JDBC类型为null
      if (mappedJdbcTypes.includeNullJdbcType()) {
        register(javaType, null, typeHandler);
      }
      // 2、如果没写这个注解，直接注册，此时JDBC类型为null
    } else {
      register(javaType, null, typeHandler);
    }
  }

  /**
   * java type + jdbc type + handler
   * @param type java类型
   * @param jdbcType jdbc类型
   * @param handler 处理器
   */
  public <T> void register(Class<T> type, JdbcType jdbcType, TypeHandler<? extends T> handler) {
    register((Type) type, jdbcType, handler);
  }

  /**
   * 注册处理器最核心的方法
   * @param javaType
   * @param jdbcType
   * @param handler
   */
  private void register(Type javaType, JdbcType jdbcType, TypeHandler<?> handler) {
    //1、若传入的 Java 类型非空
    if (javaType != null) {
      // 1.1、先尝试从 TYPE_HANDLER_MAP 集合中找到对应的映射map，
      // 若为空表示是第一次注册与该 Java 类型处理相关的处理器，则先创建java类型对应的map，再把该处理器添加进这个map中
      // 若不为空,说明已经注册过该java类型的处理器,直接把该处理器添加进这个java类型对应的map中
      // 此时如果jdbcType为null,没啥影响
      Map<JdbcType, TypeHandler<?>> map = TYPE_HANDLER_MAP.computeIfAbsent(javaType, k -> new HashMap<>());
      map.put(jdbcType, handler);
    }
    // 2、注册 handler 到 ALL_TYPE_HANDLERS_MAP 集合中。
    ALL_TYPE_HANDLERS_MAP.put(handler.getClass(), handler);
  }

  /**
   * 通过包名，批量注册类型处理器，当在 mybatis-config.xml 通过包扫描的方式注册处理器时就会调用本方法处理
   * @param packageName 包名
   */
  public void register(String packageName) {
    ResolverUtil<Class<?>> resolverUtil = new ResolverUtil<>();
    resolverUtil.find(new ResolverUtil.IsA(TypeHandler.class), packageName);
    Set<Class<? extends Class<?>>> handlerSet = resolverUtil.getClasses();
    for (Class<?> type : handlerSet) {
      // 过滤掉内部类、接口以及抽象类，调用 #register(Class<?> typeHandlerClass) 注册
      if (!type.isAnonymousClass() && !type.isInterface() && !Modifier.isAbstract(type.getModifiers())) {
        register(type);
      }
    }
  }

  /**
   * 注册类
   */
  public void register(Class<?> typeHandlerClass) {
    boolean mappedTypeFound = false;
    // 1、获得 @MappedTypes 注解,一般会在注解里写明处理的是那个javaTypeClass   例如：@MappedTypes({ String.class })
    MappedTypes mappedTypes = typeHandlerClass.getAnnotation(MappedTypes.class);
    if (mappedTypes != null) {
      for (Class<?> javaTypeClass : mappedTypes.value()) {
        register(javaTypeClass, typeHandlerClass);
        mappedTypeFound = true;
      }
    }
    // 2、未使用 @MappedTypes 注解，那就直接使用反射创建处理器实例
    if (!mappedTypeFound) {
      // 2.1 调用getInstance获得类型处理器实例对象,然后再注册
      register(getInstance(null, typeHandlerClass));
    }
  }

  /**
   * 根据传入的Java类型和类型处理器类型,创建类型处理器实例对象
   * @param javaTypeClass 待处理的Java类型
   * @param typeHandlerClass 类型处理器类型
   * @return 类型处理器实例对象
   */
  @SuppressWarnings("unchecked")
  public <T> TypeHandler<T> getInstance(Class<?> javaTypeClass, Class<?> typeHandlerClass) {
    // 1、如果传入的Java类型非空，则使用处理器类型的含参构造器创建处理器
    if (javaTypeClass != null) {
      try {
        Constructor<?> c = typeHandlerClass.getConstructor(Class.class);
        return (TypeHandler<T>) c.newInstance(javaTypeClass);
      } catch (NoSuchMethodException ignored) {
      } catch (Exception e) {
        throw new TypeException("Failed invoking constructor for handler " + typeHandlerClass, e);
      }
    }
    try {
      // 2、如果传入的Java类型为空，则使用处理器类型的默认构造器创建处理器
      Constructor<?> c = typeHandlerClass.getConstructor();
      return (TypeHandler<T>) c.newInstance();
    } catch (Exception e) {
      throw new TypeException("Unable to find a usable constructor for " + typeHandlerClass, e);
    }
  }

  // java type + handler type

  public void register(Class<?> javaTypeClass, Class<?> typeHandlerClass) {
    register(javaTypeClass, getInstance(javaTypeClass, typeHandlerClass));
  }

  /**
   * 注册类型处理器,
   * @param typeHandler 类型处理器实例
   */
  @SuppressWarnings("unchecked")
  public <T> void register(TypeHandler<T> typeHandler) {
    // 1、定义注解是否存在的标识
    boolean mappedTypeFound = false;
    // 2、查找@MappedTypes注解
    MappedTypes mappedTypes = typeHandler.getClass().getAnnotation(MappedTypes.class);
    // 3、如果找得到该注解
    if (mappedTypes != null) {
      for (Class<?> handledType : mappedTypes.value()) {
        // 3.1 获取其value作为javaType,注册处理器
        register(handledType, typeHandler);
        // 3.2、将标识改为true
        mappedTypeFound = true;
      }
    }
    // 4、如果没找到@MappedTypes注解,且该处理器是TypeReference的实例
    if (!mappedTypeFound && typeHandler instanceof TypeReference) {
      try {
        // 4.1 TypeReference中有一个字段RawType表示javaType,相当于起到了@MappedTypes的作用
        TypeReference<T> typeReference = (TypeReference<T>) typeHandler;
        // 4.2 获取其RawType作为javaType,注册处理器
        register(typeReference.getRawType(), typeHandler);
        // 4.3、将标识改为true
        mappedTypeFound = true;
      } catch (Throwable ignored) {
      }
    }
    // 5、判断该标识,根本目的是判断能不能找到javaType
    if (!mappedTypeFound) {
      // 5.1、如果找不到@MappedTypes，那就只把类型处理器注册到ALL_TYPE_HANDLERS_MAP中
      register((Class<T>) null, typeHandler);
    }
  }


  public <T> void register(TypeReference<T> javaTypeReference, TypeHandler<? extends T> handler) {
    register(javaTypeReference.getRawType(), handler);
  }

  //java type + jdbc type + handler type
  public void register(Class<?> javaTypeClass, JdbcType jdbcType, Class<?> typeHandlerClass) {
    register(javaTypeClass, jdbcType, getInstance(javaTypeClass, typeHandlerClass));
  }


  /**
   * 获取全部TypeHandler实例对象
   * @since 3.2.2
   */
  public Collection<TypeHandler<?>> getTypeHandlers() {
    // 注意是不可变容器
    return Collections.unmodifiableCollection(ALL_TYPE_HANDLERS_MAP.values());
  }

}
