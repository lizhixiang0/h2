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
package org.apache.ibatis.binding;

import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.Map;

import org.apache.ibatis.reflection.ExceptionUtil;
import org.apache.ibatis.session.SqlSession;

/**
 * 映射代理角色，使用的jdk代理
 * @author Clinton Begin
 * @author Eduardo Macarron
 */
public class MapperProxy<T> implements InvocationHandler, Serializable {

  private static final long serialVersionUID = -6424540398559729838L;
  private final SqlSession sqlSession;
  private final Class<T> mapperInterface;
  private final Map<Method, MapperMethod> methodCache;

  public MapperProxy(SqlSession sqlSession, Class<T> mapperInterface, Map<Method, MapperMethod> methodCache) {
    this.sqlSession = sqlSession;
    this.mapperInterface = mapperInterface;
    this.methodCache = methodCache;
  }

  /**
   * 这个方法就是代理方法！！！调用接口中的所有方法都等于调用本方法
   */
  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {

    if (Object.class.equals(method.getDeclaringClass())) {
      try {
        // 1、如果这个方法是Object中通用的方法（toString、hashCode等）无需执行
        // 注意：我们在构造本代理对象时，并木有传递真实角色，所以这里invoke传递的是this
        return method.invoke(this, args);
      } catch (Throwable t) {
        throw ExceptionUtil.unwrapThrowable(t);
      }
    }
    // 2、 如果不是Object中通用的方法,调用mapperMethod.execute(),这里会先从缓存中找MapperMethod
    final MapperMethod mapperMethod = cachedMapperMethod(method);
    // 2.1 这里相当将method.invoke(this, args)完全转变成了mapperMethod.execute(),本质都是进行了方法的调用，但是内涵完全不同了
    // 可以将invoke(Object proxy, Method method, Object[] args)看成一个代理方法，我们可以只是简单的在里面调用method.invoke
    // 也可以将method肢解成我们想要的MapperMethod,最终都是调用的包装方法，内涵变了而已，希望能理解。
    // 和一般的代理模式区别是，这里我们没有使用真实角色，因为Dao层没有实现类，那这里使用代理类的目的是什么？我们平时调用的那个Dao实现类是哪里来的？
    return mapperMethod.execute(sqlSession, args);
  }

  private MapperMethod cachedMapperMethod(Method method) {
    // 1、根据Method从缓存中获取对应的MapperMethod
    MapperMethod mapperMethod = methodCache.get(method);
    if (mapperMethod == null) {
      // 2、获取不到则new一个,new 的时候传递 原接口类、正在调用Method方法、从sqlSession中获取的Configuration信息
      mapperMethod = new MapperMethod(mapperInterface, method, sqlSession.getConfiguration());
      // 2.1、存放到缓存中供下一次调用
      methodCache.put(method, mapperMethod);
    }
    // 3、返回 MapperMethod
    return mapperMethod;
  }

}
