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
package org.apache.ibatis.mapping;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.session.Configuration;

/**
 * BoundSql封装mybatis最终产生sql的类，包括sql语句，参数，参数源数据等参数：
 * 其中包含sql语句(该sql语句中可能包含 ? 这样的占位符), 以及一组parameter mapping(ParameterMapping类的实例)
 * @author admin
 */
public class BoundSql {
  /**
   * 进行 #{} 和 ${} 替换完毕之后的结果sql,每个 #{}替换完之后就是一个 "?"
   */
  private String sql;
  /**
   * 参数映射
   */
  private List<ParameterMapping> parameterMappings;
  /**
   * 用户传入的数据
   */
  private Object parameterObject;
  /**
   * 这里面也是用户传递的一些数据
   */
  private Map<String, Object> additionalParameters;
  // ?
  private MetaObject metaParameters;

  public BoundSql(Configuration configuration, String sql, List<ParameterMapping> parameterMappings, Object parameterObject) {
    // 1、到达这里的sql,是已经进行 #{} 和 ${} 替换之后的sql,(注意是替换成了？)
    this.sql = sql;
    // 2、参数映射的个数, 位置都是和上面的sql中的 ? 一一对应的.
    this.parameterMappings = parameterMappings;
    // 3、用户传入的数据
    this.parameterObject = parameterObject;
    this.additionalParameters = new HashMap<>();
    this.metaParameters = configuration.newMetaObject(additionalParameters);
  }

  public String getSql() {
    return sql;
  }

  public List<ParameterMapping> getParameterMappings() {
    return parameterMappings;
  }

  public Object getParameterObject() {
    return parameterObject;
  }

  public boolean hasAdditionalParameter(String name) {
    return metaParameters.hasGetter(name);
  }

  public void setAdditionalParameter(String name, Object value) {
    metaParameters.setValue(name, value);
  }

  public Object getAdditionalParameter(String name) {
    return metaParameters.getValue(name);
  }
}
