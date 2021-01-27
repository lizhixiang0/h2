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
package org.apache.ibatis.logging;

/**
 * 日志接口
 * @author Clinton Begin
 * @description Mybatis没有提供日志的实现类，需要接入第三方的日志组件，但第三方的日志组件有自己各自的Log级别，
 *              以JDK提供的日志组件为例，输出级别为FINE,FINER,SERVRE,WARNING，这与Mybatis规定的Log接口格格不入
 *              Mybatis提供了trace、debug、warn、error四个级别,所以需要用到适配器模式
 */
public interface Log {

  /**
   * Debug,Info和Trace一般会打印比较详细的信息，而且打印的次数较多，如果我们不加log.isDebugEnabled()等
   * 进行预先判断，当系统loglevel设置高于Debug或Info或Trace时，虽然系统不会打印出这些级别的日志，但是还是会拼接
   * 参数字符串，影响系统的性能。
   *
   *  所以当要打印的debug信息比较复杂,避免浪费资源，加上isDebugEnabled方法
   *  if (log.isDebugEnabled()) {
   *      Log.debug("Input Object/List/Map:" + Object/List/Map);
   *  }
   *  或者使用字符串拼接的方式：
   *  Log.debug("Processing trade with id: {} symbol ： {} ", id, symbol);
   * @return boolean
   */
  boolean isDebugEnabled();

  /**
   *  和上面的作用一样
   * @return boolean
   */
  boolean isTraceEnabled();

  void error(String s, Throwable e);

  void error(String s);

  void debug(String s);

  void trace(String s);

  void warn(String s);

}
