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
package org.apache.ibatis.executor.statement;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.apache.ibatis.executor.parameter.ParameterHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.session.ResultHandler;

/**
 * 语句处理器
 * @author Clinton Begin
 */
public interface StatementHandler {

  /**
   * 准备语句
   * @param connection
   * @return
   * @throws SQLException
   */
  Statement prepare(Connection connection) throws SQLException;

  /**
   * 参数化
   * @param statement
   * @throws SQLException
   */
  void parameterize(Statement statement) throws SQLException;

  /**
   * 批处理
   * @param statement
   * @throws SQLException
   */
  void batch(Statement statement) throws SQLException;

  /**
   * update  (增删改)
   * @param statement
   * @return
   * @throws SQLException
   */
  int update(Statement statement) throws SQLException;

  /**
   * select-->结果给ResultHandler
   * @param statement
   * @param resultHandler
   * @param <E>
   * @return
   * @throws SQLException
   */
  <E> List<E> query(Statement statement, ResultHandler resultHandler) throws SQLException;

  /**
   * 得到绑定sql
   * @return
   */
  BoundSql getBoundSql();

  /**
   * 得到参数处理器
   * @return
   */
  ParameterHandler getParameterHandler();

}
