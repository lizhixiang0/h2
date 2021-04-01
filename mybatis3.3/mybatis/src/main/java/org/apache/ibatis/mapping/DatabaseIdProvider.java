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

import java.sql.SQLException;
import java.util.Properties;

import javax.sql.DataSource;

/**
 * 返回一个id来标识数据库的类型。可以使用该id为每种数据库类型构建不同的查询,通过这种机制来支持兼容多版本数据库
 * @author Eduardo Macarron
 */
public interface DatabaseIdProvider {
  /**
   * 设置属性
   * @param p p
   */
  void setProperties(Properties p);

  /**
   * 应该返回一个id来标识这个数据库的类型。
   */
  String getDatabaseId(DataSource dataSource) throws SQLException;
}
