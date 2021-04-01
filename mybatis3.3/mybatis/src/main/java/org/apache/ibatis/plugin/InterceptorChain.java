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
package org.apache.ibatis.plugin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 拦截器链 (责任链模式)
 * @author Clinton Begin
 */
public class InterceptorChain {

  /**
   * 存放拦截器的容器
   */
  private final List<Interceptor> interceptors = new ArrayList<>();

  /**
   * 循环调用每个Interceptor.plugin方法，层层包装
   * @param target 目标类
   * @return  层层包装后的代理类
   */
  public Object pluginAll(Object target) {
    // 循环执行了个遍，层层包装
    for (Interceptor interceptor : interceptors) {
      target = interceptor.plugin(target);
    }
    // 层层包装后的代理类
    return target;
  }

  /**
   * 添加拦截器
   * @param interceptor 拦截器
   */
  public void addInterceptor(Interceptor interceptor) {
    interceptors.add(interceptor);
  }

  /**
   * 获得所有拦截器（不可变队形）
   * @return List<Interceptor>
   */
  public List<Interceptor> getInterceptors() {
    return Collections.unmodifiableList(interceptors);
  }

}
