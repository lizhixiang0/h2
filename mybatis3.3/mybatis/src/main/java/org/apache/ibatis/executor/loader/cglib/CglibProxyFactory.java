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
package org.apache.ibatis.executor.loader.cglib;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import net.sf.cglib.proxy.Callback;
import net.sf.cglib.proxy.Enhancer;
import net.sf.cglib.proxy.MethodInterceptor;
import net.sf.cglib.proxy.MethodProxy;

import org.apache.ibatis.executor.loader.AbstractEnhancedDeserializationProxy;
import org.apache.ibatis.executor.loader.AbstractSerialStateHolder;
import org.apache.ibatis.executor.loader.ProxyFactory;
import org.apache.ibatis.executor.loader.ResultLoaderMap;
import org.apache.ibatis.executor.loader.WriteReplaceInterface;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;
import org.apache.ibatis.reflection.ExceptionUtil;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.reflection.property.PropertyCopier;
import org.apache.ibatis.reflection.property.PropertyNamer;
import org.apache.ibatis.session.Configuration;

/**
 * Cglib延迟加载代理工厂
 * @author Clinton Begin
 */
public class CglibProxyFactory implements ProxyFactory {

  private static final Log log = LogFactory.getLog(CglibProxyFactory.class);
  private static final String FINALIZE_METHOD = "finalize";
  /**
   * 懒加载与序列化问题
   * https://blog.csdn.net/qq_33762302/article/details/115364535
   * 文中的解释逻辑不清晰,我觉得从代码角度看是因为,如果延迟加载的属性全部加载完了，那此时直接序列化原始类即可
   * 如果该对象还存在某些属性未加载，那么应该序列化代理对象！那就要稍微复杂一点。
   */
  private static final String WRITE_REPLACE_METHOD = "writeReplace";

  public CglibProxyFactory() {
    try {
      // 加载Enhancer来检查是否有Cglib的包
      Resources.classForName("net.sf.cglib.proxy.Enhancer");
    } catch (Throwable e) {
      throw new IllegalStateException("Cannot enable lazy loading because CGLIB is not available. Add CGLIB to your classpath.", e);
    }
  }

  /**
   * 创建代理对象
   * @param target 目标对象
   * @param lazyLoader 延迟加载器
   * @param configuration 配置类
   * @param objectFactory 对象工厂
   * @param constructorArgTypes 构造函数类型[]
   * @param constructorArgs  构造函数的值[]
   */
  @Override
  public Object createProxy(Object target, ResultLoaderMap lazyLoader, Configuration configuration, ObjectFactory objectFactory, List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
    return EnhancedResultObjectProxyImpl.createProxy(target, lazyLoader, configuration, objectFactory, constructorArgTypes, constructorArgs);
  }
  /**
   * 创建一个反序列化代理
   * @param target 目标
   * @param unloadedProperties 未加载的属性
   * @param objectFactory 对象工厂
   * @param constructorArgTypes 构造函数类型数组
   * @param constructorArgs 构造函数值
   */
  public Object createDeserializationProxy(Object target, Map<String, ResultLoaderMap.LoadPair> unloadedProperties, ObjectFactory objectFactory, List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
    return EnhancedDeserializationProxyImpl.createProxy(target, unloadedProperties, objectFactory, constructorArgTypes, constructorArgs);
  }

  @Override
  public void setProperties(Properties properties) {
      // Not Implemented
  }

  /**
   * 创建代理对象
   * Enhancer 认为这个就是自定义类的工厂，比如这个类需要实现什么接口
   * @param type 目标类型
   * @param callback 结果对象代理实现类，当中有invoke回调方法
   * @param constructorArgTypes 构造函数类型数组
   * @param constructorArgs 构造函数对应字段的值数组
   * @return
   */
  static Object crateProxy(Class<?> type, Callback callback, List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
    // 1、创建cglib的增强类（这玩意就像一个对象工厂，配置代理对象需要的一些参数来生成代理对象）
	Enhancer enhancer = new Enhancer();
	// 2、设置父类,就是真实角色
    enhancer.setSuperclass(type);
    // 3、设置代理角色（设置回调方法，调用任何方法都会先调用代理角色的intercept方法）
    enhancer.setCallback(callback);
    try {
      // 4、判断原始对象有没有声明writeReplace方法
      type.getDeclaredMethod(WRITE_REPLACE_METHOD);
      log.debug(WRITE_REPLACE_METHOD + " method was found on bean " + type + ", make sure it returns this");
    } catch (NoSuchMethodException e) {
      // 4.1 、原始对象没声明writeReplace方法,则给代理对象增加一个WriteReplaceInterface接口
      enhancer.setInterfaces(new Class[]{WriteReplaceInterface.class});
    } catch (SecurityException ignored) {
    }
    // 5、声明一个代理对象,Enhancer配置好了,下面开始创建代理对象了，无非就是分有参构造和无参构造
    Object enhanced = null;
    if (constructorArgTypes.isEmpty()) {
      // 5.1 通过无参构造创建对象
      enhanced = enhancer.create();
    } else {
      Class<?>[] typesArray = constructorArgTypes.toArray(new Class[constructorArgTypes.size()]);
      Object[] valuesArray = constructorArgs.toArray(new Object[constructorArgs.size()]);
      // 5.2 通过有参构造创建对象
      enhanced = enhancer.create(typesArray, valuesArray);
    }
    // 6、返回代理对象，注意此时代理对象是有声明writeReplace方法的
    return enhanced;
  }

  /**
   * 静态内部类
   * 代理角色,实现MethodInterceptor,重写intercept
   */
  private static class EnhancedResultObjectProxyImpl implements MethodInterceptor {
    // 真实对象的类
    private Class<?> type;
    // 这是干啥？？
    private ResultLoaderMap lazyLoader;
    // 如果aggressiveLazyLoading=true,只要触发到对象任何的方法，就会立即加载所有属性的加载
    private boolean aggressive;
    // 指定调用对象的哪些方法前触发一次数据加载
    private Set<String> lazyLoadTriggerMethods;
    // 对象工厂,善于创建对象
    private ObjectFactory objectFactory;
    // 构造函数参数类型列表
    private List<Class<?>> constructorArgTypes;
    // 构造函数参数值列表
    private List<Object> constructorArgs;

    /**
     * 代理角色创建
     * @param type 目标class类型
     * @param lazyLoader 延迟加载器
     * @param configuration 配置信息
     * @param objectFactory 对象工厂
     * @param constructorArgTypes 构造函数类型数组
     * @param constructorArgs 构造函数值数组
     */
    private EnhancedResultObjectProxyImpl(Class<?> type, ResultLoaderMap lazyLoader, Configuration configuration, ObjectFactory objectFactory, List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
      this.type = type;
      this.lazyLoader = lazyLoader;
      this.aggressive = configuration.isAggressiveLazyLoading();
      this.lazyLoadTriggerMethods = configuration.getLazyLoadTriggerMethods();
      this.objectFactory = objectFactory;
      this.constructorArgTypes = constructorArgTypes;
      this.constructorArgs = constructorArgs;
    }

    /**
     * 最核心的拦截器方法,在调用真实对象的方法之前,都会先调用这个intercept方法
     * @param enhanced 增强类,这玩意儿就是生成的增强类
     * @param method 原始方法 ,这个方法么得用
     * @param args 方法参数
     * @param methodProxy 代理后的方法
     */
    @Override
    public Object intercept(Object enhanced, Method method, Object[] args, MethodProxy methodProxy) throws Throwable {
      // 1、获取方法名
      final String methodName = method.getName();
      try {
        // 2、这里用了个线程锁,强制排队
        synchronized (lazyLoader) {
          // 3、如果是执行writeReplace方法(什么时候会执行这个方法？）
          if (WRITE_REPLACE_METHOD.equals(methodName)) {
            // 3.1、创建原始类对象,分有参和无参
            Object original = null;
            if (constructorArgTypes.isEmpty()) {
              original = objectFactory.create(type);
            } else {
              original = objectFactory.create(type, constructorArgTypes, constructorArgs);
            }
            // 将增强后的类属性赋值给原始对象
            PropertyCopier.copyBeanProperties(type, enhanced, original);
            // 假如该对象中存在某些属性是懒加载属性,会构建并返回返回CglibSerialStateHolder对象
            if (lazyLoader.size() > 0) {
              return new CglibSerialStateHolder(original, lazyLoader.getProperties(), objectFactory, constructorArgTypes, constructorArgs);
            } else {
              return original;
            }
          } else {
            //4、不是writeReplace方法和finalize方法,且存在属性需要延迟加载
            if (lazyLoader.size() > 0 && !FINALIZE_METHOD.equals(methodName)) {
              // 4.1、如果配置类里配置了积极加载或者该方法是指定必触发数据全部加载的方法
              if (aggressive || lazyLoadTriggerMethods.contains(methodName)) {
                // 4.1.1、触发数据加载,加载所有属性
                lazyLoader.loadAll();

                // 4.2、如果未配置积极加载,且未配置成必触发数据全部加载的方法,则判断是否是getter、setter、isBoolean之类的方法
              } else if (PropertyNamer.isProperty(methodName)) {
              	// 4.3、getName , setName  ,去掉前缀
                final String property = PropertyNamer.methodToProperty(methodName);
                if (lazyLoader.hasLoader(property)) {
                  // 4.4、加载指定属性
                  lazyLoader.load(property);
                }
              }
            }
          }
        }
        // 加载完,才调用真实对象的方法
        return methodProxy.invokeSuper(enhanced, args);
      } catch (Throwable t) {
        throw ExceptionUtil.unwrapThrowable(t);
      }
    }

    /**
     * 不晓得作者为啥非得把这个静态方法放到 代理类里面，这样特别容易造成困扰，直接放到CglibProxyFactory明明也可以。
     */
    public static Object createProxy(Object target, ResultLoaderMap lazyLoader, Configuration configuration, ObjectFactory objectFactory, List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
      // 1、取得真实角色类型
      final Class<?> type = target.getClass();
      // 2、创建代理角色
      EnhancedResultObjectProxyImpl callback = new EnhancedResultObjectProxyImpl(type, lazyLoader, configuration, objectFactory, constructorArgTypes, constructorArgs);
      // 3、通过cglib的Enhancer来创建代理类
      Object enhanced = crateProxy(type, callback, constructorArgTypes, constructorArgs);
      // 4、将target中的属性都赋值给代理类
      PropertyCopier.copyBeanProperties(type, target, enhanced);
      // 5、返回代理类
      return enhanced;
    }
  }

  private static class EnhancedDeserializationProxyImpl extends AbstractEnhancedDeserializationProxy implements MethodInterceptor {

    private EnhancedDeserializationProxyImpl(Class<?> type, Map<String, ResultLoaderMap.LoadPair> unloadedProperties, ObjectFactory objectFactory,
            List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
      super(type, unloadedProperties, objectFactory, constructorArgTypes, constructorArgs);
    }

    public static Object createProxy(Object target, Map<String, ResultLoaderMap.LoadPair> unloadedProperties, ObjectFactory objectFactory,
            List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
      final Class<?> type = target.getClass();
      EnhancedDeserializationProxyImpl callback = new EnhancedDeserializationProxyImpl(type, unloadedProperties, objectFactory, constructorArgTypes, constructorArgs);
      Object enhanced = crateProxy(type, callback, constructorArgTypes, constructorArgs);
      PropertyCopier.copyBeanProperties(type, target, enhanced);
      return enhanced;
    }

    @Override
    public Object intercept(Object enhanced, Method method, Object[] args, MethodProxy methodProxy) throws Throwable {
      final Object o = super.invoke(enhanced, method, args);
      return (o instanceof AbstractSerialStateHolder) ? o : methodProxy.invokeSuper(o, args);
    }

    @Override
    protected AbstractSerialStateHolder newSerialStateHolder(Object userBean, Map<String, ResultLoaderMap.LoadPair> unloadedProperties, ObjectFactory objectFactory,
            List<Class<?>> constructorArgTypes, List<Object> constructorArgs) {
      return new CglibSerialStateHolder(userBean, unloadedProperties, objectFactory, constructorArgTypes, constructorArgs);
    }
  }
}
