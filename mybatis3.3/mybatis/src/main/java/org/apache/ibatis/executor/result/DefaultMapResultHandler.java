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

import java.util.Map;

import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.reflection.wrapper.ObjectWrapperFactory;
import org.apache.ibatis.session.ResultContext;
import org.apache.ibatis.session.ResultHandler;

/**
 * 默认Map结果处理器
 * @author Clinton Begin
 */
public class DefaultMapResultHandler<K, V> implements ResultHandler {

  /**
   * 内部维护了一个Map集合,<k,v>中 key是指定的mapKey对应的值,value是该记录
   */
  private final Map<K, V> mappedResults;
  /**
   * 集合中的记录以那个字段为key,通常应该是属性名
   */
  private final String mapKey;
  /**
   * 对象工厂
   */
  private final ObjectFactory objectFactory;
  /**
   * 对象包装器工厂
   */
  private final ObjectWrapperFactory objectWrapperFactory;

  @SuppressWarnings("unchecked")
  public DefaultMapResultHandler(String mapKey, ObjectFactory objectFactory, ObjectWrapperFactory objectWrapperFactory) {
    this.objectFactory = objectFactory;
    this.objectWrapperFactory = objectWrapperFactory;
    // 默认的对象工厂是创建HashMap对象
    this.mappedResults = objectFactory.create(Map.class);
    this.mapKey = mapKey;
  }

  /**
   * 核心方法, 主要目的是把得到的List转为Map
   * @param context 结果上下文
   */
  @Override
  public void handleResult(ResultContext context) {
    // 获取记录
    final V value = (V) context.getResultObject();
    // 用MetaObject.forObject,包装一下记录
    final MetaObject mo = MetaObject.forObject(value, objectFactory, objectWrapperFactory);
    // 根据属性名获得该属性名对应的value
    final K key = (K) mo.getValue(mapKey);
    mappedResults.put(key, value);
  }

  public Map<K, V> getMappedResults() {
    return mappedResults;
  }
}
