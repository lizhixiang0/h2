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
   * 内部维护了一个Map<k,v>集合
   * key: 指定的mapKey对应的值,
   * value: mapKey对应的记录
   */
  private final Map<K, V> mappedResults;
  /**
   * 集合中的记录以那个字段为key,通常是属性名
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
    // 利用对象工厂创建Map对象
    this.mappedResults = objectFactory.create(Map.class);
    this.mapKey = mapKey;
  }

  /**
   * 核心方法, 把查询得到的List转为Map
   * @param context 结果上下文  ,list结果集合中的某一条记录
   */
  @Override
  public void handleResult(ResultContext context) {
    // 1、获取记录
    final V value = (V) context.getResultObject();
    // 2、用MetaObject包装下记录
    final MetaObject mo = MetaObject.forObject(value, objectFactory, objectWrapperFactory);
    // 3、获得mapKey的value
    final K key = (K) mo.getValue(mapKey);
    // 4、存入map集合
    mappedResults.put(key, value);
  }

  /**
   * 获得处理后的map结果集
   * @return map
   */
  public Map<K, V> getMappedResults() {
    return mappedResults;
  }
}
