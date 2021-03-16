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
package org.apache.ibatis.binding;

import org.apache.ibatis.builder.annotation.MapperAnnotationBuilder;
import org.apache.ibatis.io.ResolverUtil;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSession;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 映射器注册机
 * mapper注册器用于将所有的mapper接口添加到内存中,Mapper注册器自身维护着两个属性，config和knownMappers,
 *
 * @author admin
 */
public class MapperRegistry {

  private Configuration config;

  /**
   * <k,v>
   *     k :类路径
   *     v : 对应的Mapper代理工厂
   *         MapperProxyFactory的工作就是通过代理模式创建处一个MapperProxy代理类
   *         MapperProxy实现了InvocationHandler接口,MapperProxy可以通过invoke()方法实现Mapper接口指定方法的调用,
   *         这意味着MapperProxy并不直接实现Mapper接口的调用,而是在内部维系着一个<Mapper.Method,MapperMethod>的map集合,
   */
  private final Map<Class<?>, MapperProxyFactory<?>> knownMappers = new HashMap<>();

  public MapperRegistry(Configuration config) {
    this.config = config;
  }

  @SuppressWarnings("unchecked")
  public <T> T getMapper(Class<T> type, SqlSession sqlSession) {
    // 1、获取mapper代理工厂类
    final MapperProxyFactory<T> mapperProxyFactory = (MapperProxyFactory<T>) knownMappers.get(type);
    // 2、在map中找不到则表示没有将mapper类注册进来,抛出BindingException
    if (mapperProxyFactory == null) {
      throw new BindingException("Type " + type + " is not known to the MapperRegistry.");
    }
    try {
      // 3、使用代理工厂创建一个mapper代理类实例(本质上是通过代理模式创建了一个代理类)
      return mapperProxyFactory.newInstance(sqlSession);
    } catch (Exception e) {
      // 3.1 创建过程中出现异常抛出BindingException
      throw new BindingException("Error getting mapper instance. Cause: " + e, e);
    }
  }

  public <T> boolean hasMapper(Class<T> type) {
    return knownMappers.containsKey(type);
  }

  /**
   * 添加一个映射
   * @param type 接口类
   * @param <T>
   */
  public <T> void addMapper(Class<T> type) {
    // 1、首先排除非接口的类
    if (type.isInterface()) {
      // 1.1 判断是否已经注册过
      if (hasMapper(type)) {
        throw new BindingException("Type " + type + " is already known to the MapperRegistry.");
      }
      // 1.2 定义一个标识
      boolean loadCompleted = true;
      try {
        // 1.3 将mapper接口注册到konowMappers中 ,konowMappers是一个Map集合，用于存储接口和接口的代理类工厂
        knownMappers.put(type, new MapperProxyFactory<T>(type));
        // 1.4 实例化MapperAnnotationBuilder类，该类的作用是解析注解配置sql的。先跳过，todo
        MapperAnnotationBuilder parser = new MapperAnnotationBuilder(config, type);
        parser.parse();
        // 1.5 注册成功，改变标识
        loadCompleted = false;
      } finally {
        // 1.6 标识没变，说明try{...}中如果有异常,需要删除放入knownMappers的接口
        if (loadCompleted) {
          knownMappers.remove(type);
        }
      }
    }
  }

  /**
   * @since 3.2.2
   */
  public Collection<Class<?>> getMappers() {
    // Collections.unmodifiableCollection() 可以得到一个knownMappers集合的镜像（不可变对象）
    // 后续在操作knownMappers时,该镜像也会随之改变，不能直接操作该镜像
    return Collections.unmodifiableCollection(knownMappers.keySet());
  }

  /**
   * 查找包下所有为superType的类 （子类或其本身）
   * @since 3.2.2
   */
  public void addMappers(String packageName, Class<?> superType) {
    // 1、创建一个类路径解析器
    ResolverUtil<Class<?>> resolverUtil = new ResolverUtil<>();
      // 1.1 构造一个IsA内部类,传递到find()方法中,这种写法可以学习
    resolverUtil.find(new ResolverUtil.IsA(superType), packageName);
      // 1.2 获得根据指定条件从包中找到的所有类
    Set<Class<? extends Class<?>>> mapperSet = resolverUtil.getClasses();
    // 2、循环遍历这些接口和类，调用addMapper(mapperClass)方法，可以认为本方法是addMapper(mapperClass)的批量操作，将整个包下的接口一次性配置。
    for (Class<?> mapperClass : mapperSet) {
      addMapper(mapperClass);
    }
  }

  /**
   * 查找包下所有父类为Object.class的类 ，其实就是所有类
   * @since 3.2.2
   */
  public void addMappers(String packageName) {
    addMappers(packageName, Object.class);
  }

}
