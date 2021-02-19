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
package org.apache.ibatis.reflection;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.UndeclaredThrowableException;

/**
 * 异常工具
 * @author Clinton Begin
 */
public class ExceptionUtil {

  private ExceptionUtil() {}

  /**
   * 找到真正的异常
   *
   * 1、InvocationTargetException  ：由Method.invoke(obj, args...)方法抛出。当被调用的方法的内部抛出了异常而没有被捕获时，将由此异常接收！！！使用getTargetException()获得真正的异常
   *      @blog "https://www.cnblogs.com/yjd_hycf_space/p/7765748.html
   *
   * 2、UndeclaredThrowableException  ：被代理的方法抛出了检查型异常(exception)，而代理类在处理异常时没有发现该类型的异常在接口中声明，则会使用UndeclaredThrowableException将该异常包装起来。可以使用getUndeclaredThrowable()获得
   *      @blog "https://blog.csdn.net/ywlmsm1224811/article/details/92618062
   *
   * @param wrapped
   * @return
   */
  public static Throwable unwrapThrowable(Throwable wrapped) {
    Throwable unwrapped = wrapped;
    while (true) {
      if (unwrapped instanceof InvocationTargetException) {
        unwrapped = ((InvocationTargetException) unwrapped).getTargetException();
      } else if (unwrapped instanceof UndeclaredThrowableException) {
        unwrapped = ((UndeclaredThrowableException) unwrapped).getUndeclaredThrowable();
      } else {
        return unwrapped;
      }
    }
  }

}
