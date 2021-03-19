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
package org.apache.ibatis.exceptions;

import org.apache.ibatis.executor.ErrorContext;

/**
 * 异常工厂
 * @author Clinton Begin
 */
public class ExceptionFactory {

  private ExceptionFactory() {}

  /**
   * 把普通异常包装成mybatis自己的PersistenceException
   */
  public static RuntimeException wrapException(String message, Exception e) {
    // 这边使用ErrorContext结合建造者模式,一步步构建错误信息，比单纯的传递一个message要那么一点。
    message  = ErrorContext.instance().message(message).cause(e).toString();
    return new PersistenceException(message, e);
  }

}
