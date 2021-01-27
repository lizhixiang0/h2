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
package org.apache.ibatis.logging.commons;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * 用的commons logging里的Log和LogFactory,简称JCL
 * JCL其实是一个抽象日志，它自己并不提供日志功能，而是从已有的日志（在一个有序的数组中）中按顺序选择一个！通过全限定名反射创建对象返回
 * 比如我们的pom文件里log4j的依赖，所以能够创建log4j对象！如果没有，则选择jdk1.4提供的jul,使用jcl的好处显而易见
 * 缺点是：它默认兼容的日志类型，就两种，一个log4j，一个jul！
 * @author Clinton Begin
 */
public class JakartaCommonsLoggingImpl implements org.apache.ibatis.logging.Log {

  private Log log;

  public JakartaCommonsLoggingImpl(String clazz) {
    log = LogFactory.getLog(clazz);
  }

  @Override
  public boolean isDebugEnabled() {
    return log.isDebugEnabled();
  }

  @Override
  public boolean isTraceEnabled() {
    return log.isTraceEnabled();
  }

  @Override
  public void error(String s, Throwable e) {
    log.error(s, e);
  }

  @Override
  public void error(String s) {
    log.error(s);
  }

  @Override
  public void debug(String s) {
    log.debug(s);
  }

  @Override
  public void trace(String s) {
    log.trace(s);
  }

  @Override
  public void warn(String s) {
    log.warn(s);
  }

}
