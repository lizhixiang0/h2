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

import org.apache.ibatis.session.ResultContext;

/**
 * 默认结果上下文(处理查询结果)
 *
 * @author Clinton Begin
 */
public class DefaultResultContext implements ResultContext {
  /**
   * 记录当前记录
   */
  private Object resultObject;
  /**
   * 记录处理到第几个记录
   */
  private int resultCount;

  /**
   *
   */
  private boolean stopped;

  /**
   * 唯一构造方法
   */
  public DefaultResultContext() {
    resultObject = null;
    resultCount = 0;
    stopped = false;
  }

  /**
   * 每次调用nextResultObject这个方法，设置resultObject,并且内部count自增1
   * @param resultObject 查询结果
   */
  public void nextResultObject(Object resultObject) {
    resultCount++;
    this.resultObject = resultObject;
  }

  @Override
  public void stop() {
    this.stopped = true;
  }

  @Override
  public Object getResultObject() {
    return resultObject;
  }

  @Override
  public int getResultCount() {
    return resultCount;
  }

  @Override
  public boolean isStopped() {
    return stopped;
  }

}
