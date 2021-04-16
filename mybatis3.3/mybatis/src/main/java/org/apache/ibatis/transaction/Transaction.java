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
package org.apache.ibatis.transaction;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * 事务管理接口
 * 处理数据库连接的生命周期,包括它的创建、准备、提交、回滚、关闭。在 MyBatis 中有两种事务管理器类型(JDBC、MANAGED):
 *
 * @author Clinton Begin
 */
public interface Transaction {

  /**
   * 获得数据库连接
   */
  Connection getConnection() throws SQLException;

  /**
   * 数据库提交
   */
  void commit() throws SQLException;

  /**
   * 数据库回滚
   */
  void rollback() throws SQLException;

  /**
   * 关闭数据库连接
   */
  void close() throws SQLException;

}
