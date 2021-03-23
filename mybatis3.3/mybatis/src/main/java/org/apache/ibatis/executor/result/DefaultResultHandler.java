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
package org.apache.ibatis.executor.result;

import java.util.ArrayList;
import java.util.List;

import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.session.ResultContext;
import org.apache.ibatis.session.ResultHandler;

/**
 * 默认结果处理器
 * @author Clinton Begin
 */
public class DefaultResultHandler implements ResultHandler {

  /**
   * 内部维护了一个集合容器,实例化时初始化
   */
  private final List<Object> list;

  /**
   * 构造方法 1
   */
  public DefaultResultHandler() {
    // 创建对象的时候初始化了个ArrayList集合容器
    list = new ArrayList<>();
  }

  /**
   * 构造方法 2
   */
  @SuppressWarnings("unchecked")
  public DefaultResultHandler(ObjectFactory objectFactory) {
    // 或者由对象工厂来创建集合容器,默认的对象工厂还是创建的ArrayList
    list = objectFactory.create(List.class);
  }

  /**
   * 核心方法  ，//啥都没干,就是把结果从ResultContext拿出来然后add进handler的容器里去
   */
  @Override
  public void handleResult(ResultContext context) {
    list.add(context.getResultObject());
  }

  public List<Object> getResultList() {
    return list;
  }

}
