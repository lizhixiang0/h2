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
package org.apache.ibatis.logging;

import java.lang.reflect.Constructor;

/**
 * 日志工厂
 * @author Clinton Begin
 * @author Eduardo Macarron
 * @description 通过适配器模式，实现了集成和复用常见的第三方日志组件。优先级由高到低为slf4J、common logging、Log4J2、Log4J和jdk logging
 * @note   适配器模式：解决由于接口不能兼容而导致类无法使用的问题，将需要适配的类转换成调用者能够使用的目标接口
 * @blog   "https://blog.csdn.net/hou_ge/article/details/100556022
 */
public final class LogFactory {

  /**
   * Marker to be used by logging implementations that support markers
   * 给支持marker功能的logger使用(目前有slf4j, log4j2)
   * @blog "https://logging.apache.org/log4j/2.x/manual/markers.html
   * @note 个人理解是为了提供标记信息用来过滤日志,方便调试和调错
   */
  public static final String MARKER = "MYBATIS";

  /**
   * 记录当前使用的第三方日志组件所对应的适配器的构造方法
   */
  private static Constructor<? extends Log> logConstructor;

  static {
    //slf4j
    tryImplementation(LogFactory::useSlf4jLogging);
    //common logging
    tryImplementation(LogFactory::useCommonsLogging);
    //log4j2
    tryImplementation(LogFactory::useLog4J2Logging);
    //log4j
    tryImplementation(LogFactory::useLog4JLogging);
    //jdk logging
    tryImplementation(LogFactory::useJdkLogging);
    //没有日志
    tryImplementation(LogFactory::useNoLogging);
  }

  private static void tryImplementation(Runnable runnable) {
    // logConstructor为空才继续执行，所以一般就只执行第一次tryImplementation,通过这种方式控制了第三方日志插件加载的优先级。
    if (logConstructor == null) {
      try {
        //调用的run,没用多线程
        runnable.run();
      } catch (Throwable ignored) {
      }
    }
  }

  public static synchronized void useSlf4jLogging() {
    setImplementation(org.apache.ibatis.logging.slf4j.Slf4jImpl.class);
  }

  public static synchronized void useCommonsLogging() {
    setImplementation(org.apache.ibatis.logging.commons.JakartaCommonsLoggingImpl.class);
  }

  public static synchronized void useLog4JLogging() {
    setImplementation(org.apache.ibatis.logging.log4j.Log4jImpl.class);
  }

  public static synchronized void useLog4J2Logging() {
    setImplementation(org.apache.ibatis.logging.log4j2.Log4j2Impl.class);
  }

  public static synchronized void useJdkLogging() {
    setImplementation(org.apache.ibatis.logging.jdk14.Jdk14LoggingImpl.class);
  }

  public static synchronized void useStdOutLogging() {
    setImplementation(org.apache.ibatis.logging.stdout.StdOutImpl.class);
  }

  public static synchronized void useNoLogging() {
    setImplementation(org.apache.ibatis.logging.nologging.NoLoggingImpl.class);
  }

  /**
   * 加载这个LogFactory类时会自动执行静态代码块中的代码,自动按优先级去搜索发现jar包
   * 但是支持用户自己选择一个日志类,如下
   * <settings>
   *        <setting name="logImpl" value="STDOUT_LOGGING"/>
   * </settings>
   * @param clazz 类对象
   */
  public static synchronized void useCustomLogging(Class<? extends Log> clazz) {
    setImplementation(clazz);
  }


  private static void setImplementation(Class<? extends Log> implClass) {
    try {
      //获取有参构造,这些适配器的构造器都是一个String类型的单参构造器
      Constructor<? extends Log> candidate = implClass.getConstructor(String.class);
      Log log = candidate.newInstance(LogFactory.class.getName());
      log.debug("Logging initialized using '" + implClass + "' adapter.");
      //设置logConstructor,一旦设上，表明找到相应的log的jar包了，那后面别的log就不找了。如果找不到就报异常，然后继续找。。。
      logConstructor = candidate;
    } catch (Throwable t) {
      throw new LogException("Error setting Log implementation.  Cause: " + t, t);
    }
  }

  /**
   * 构造函数私有化----------->单例模式
   */
  private LogFactory() {}

  /**
   * 根据传入的类来构建Log
   * @param aClass 类
   */
  public static Log getLog(Class<?> aClass) {
    return getLog(aClass.getName());
  }

  /**
   * @param logger 参数
   * @note 注意这个logger参数是logConstructor有参构造函数的参数,不是日志的全限定名
   */
  public static Log getLog(String logger) {
    try {
      return logConstructor.newInstance(logger);
    } catch (Throwable t) {
      throw new LogException("Error creating logger for logger " + logger + ".  Cause: " + t, t);
    }
  }
}
