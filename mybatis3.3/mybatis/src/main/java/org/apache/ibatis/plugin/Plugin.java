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
package org.apache.ibatis.plugin;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.reflection.ExceptionUtil;

/**
 * 插件  （利用动态代理,改变方法行为）
 * @author Clinton Begin
 */
public class Plugin implements InvocationHandler {
  /**
   * 目标对象
   */
  private Object target;
  /**
   * 拦截器对象
   */
  private Interceptor interceptor;
  /**
   * 目标对象方法签名
   */
  private Map<Class<?>, Set<Method>> signatureMap;

  /**
   * 构造方法私有化
   */
  private Plugin(Object target, Interceptor interceptor, Map<Class<?>, Set<Method>> signatureMap) {
    this.target = target;
    this.interceptor = interceptor;
    this.signatureMap = signatureMap;
  }

  /**
   * 主要是调用本方法,创建plugin代理
   * @param target 目标方法
   * @param interceptor 自定义的拦截器
   * @return ？？
   */
  public static Object wrap(Object target, Interceptor interceptor) {
    // 1、从拦截器的@Signature注解中取出需要被拦截的类名和方法等信息
    Map<Class<?>, Set<Method>> signatureMap = getSignatureMap(interceptor);
    // 2、获取被拦截改变行为的目标类的类型 (一般是：ParameterHandler、ResultSetHandler、StatementHandler、Executor)
    Class<?> type = target.getClass();
    // 3、解析被拦截对象的所有接口
    Class<?>[] interfaces = getAllInterfaces(type, signatureMap);
    // 4、如果接口数大于0，则生成代理对象并返回，Plugin对象为该代理对象的InvocationHandler  （这里可以看到jdk动态代理是必须得有接口的）
    if (interfaces.length > 0) {
      return Proxy.newProxyInstance(
          type.getClassLoader(),
          interfaces,
          new Plugin(target, interceptor, signatureMap));
    }
    // 5、否则返回目标对象
    return target;
  }


  /**
   * 从@Intercepts中取出@Signature,再从@Signature中取出需要被拦截的类、方法等信息
   */
  private static Map<Class<?>, Set<Method>> getSignatureMap(Interceptor interceptor) {
    // 1、取Intercepts注解
    Intercepts interceptsAnnotation = interceptor.getClass().getAnnotation(Intercepts.class);
    // 2、必须得有Intercepts注解，没有报错
    if (interceptsAnnotation == null) {
      throw new PluginException("No @Intercepts annotation was found in interceptor " + interceptor.getClass().getName());
    }
    // 3、取出@Intercepts所有值,用@Signature数组来接（可能会配置多个@Signature）
    Signature[] sigs = interceptsAnnotation.value();
    // 4、创建容器,注意是<Class<?>, Set<Method>>,因为可能配置的多个@Signature里，存在两个@Signature同类但方法不同
    Map<Class<?>, Set<Method>> signatureMap = new HashMap<>(16);
    // 5、遍历@Signature数组
    for (Signature sig : sigs) {
      // a、先把clazz和对应的空set放进容器（已存在clazz不创建新的set）
      Set<Method> methods = signatureMap.computeIfAbsent(sig.type(), k -> new HashSet<>());
      try {
        // b、根据方法名和参数获取方法
        Method method = sig.type().getMethod(sig.method(), sig.args());
        // c、将该方法加入set容器
        methods.add(method);
      } catch (NoSuchMethodException e) {
        throw new PluginException("Could not find method on " + sig.type() + " named " + sig.method() + ". Cause: " + e, e);
      }
    }
    // 6、返回签名信息
    return signatureMap;
  }

  /**
   * 取得所有接口用来进行jdk动态代理
   * @param type 目标类
   * @param signatureMap 签名信息
   * @return 接口集合
   */
  private static Class<?>[] getAllInterfaces(Class<?> type, Map<Class<?>, Set<Method>> signatureMap) {
    // 1、创建接口类容器
    Set<Class<?>> interfaces = new HashSet<>();
    // 2、while循环
    while (type != null) {
      for (Class<?> c : type.getInterfaces()) {
        // 只有signatureMap中存在的clazz ，才会被添加到interfaces
        if (signatureMap.containsKey(c)) {
          interfaces.add(c);
        }
      }
      // 继续挖掘,接口的父类也要取出来
      type = type.getSuperclass();
    }
    return interfaces.toArray(new Class<?>[0]);
  }

  /**
   * 这就是插件的底层：利用动态代理,改变方法行为
   */
  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    try {
      // 1、判断该方法是不是拦截器中@Signature注解里配置的应该被拦截的方法
      Set<Method> methods = signatureMap.get(method.getDeclaringClass());
      if (methods != null && methods.contains(method)) {
        //1.1 、如果是就调用Interceptor.intercept，即插入了我们自己的逻辑
        return interceptor.intercept(new Invocation(target, method, args));
      }
      // 2、如果该方法不是应该被拦截的方法,就执行原来逻辑
      return method.invoke(target, args);
    } catch (Exception e) {
      throw ExceptionUtil.unwrapThrowable(e);
    }
  }

}
