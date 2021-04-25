/*
 *    Copyright 2009-2014 the original author or authors.
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
package org.apache.ibatis.executor;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.List;

import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.logging.Log;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.transaction.Transaction;

/**
 * 简单执行器
 * @author Clinton Begin
 */
public class SimpleExecutor extends BaseExecutor {

  public SimpleExecutor(Configuration configuration, Transaction transaction) {
    super(configuration, transaction);
  }

  /**
   * update  (增删改最终都调用这个方法)
   * @param ms  sql映射语句
   * @param parameter  参数
   * @return
   * @throws SQLException
   */
  @Override
  public int doUpdate(MappedStatement ms, Object parameter) throws SQLException {
    Statement stmt = null;
    try {
      Configuration configuration = ms.getConfiguration();
      // 1、新建SimpleStatementHandler
      StatementHandler handler = configuration.newStatementHandler(this, ms, parameter, RowBounds.DEFAULT, null, null);
      // 2、创建Statement
      stmt = prepareStatement(handler, ms.getStatementLog());
      // 3、执行语句
      return handler.update(stmt);
    } finally {
      // 4、关闭statement (一般最好是先关闭resultSet（如果有），在关闭statement，最后才关闭connection)
      closeStatement(stmt);
    }
  }

  /**
   * 查询
   * @param ms
   * @param parameter
   * @param rowBounds
   * @param resultHandler
   * @param boundSql
   * @param <E>
   * @return
   * @throws SQLException
   */
  @Override
  public <E> List<E> doQuery(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler, BoundSql boundSql) throws SQLException {
    Statement stmt = null;
    try {
      Configuration configuration = ms.getConfiguration();
      // 1、创建SimpleStatementHandler
      StatementHandler handler = configuration.newStatementHandler(wrapper, ms, parameter, rowBounds, resultHandler, boundSql);
      // 2、准备语句
      stmt = prepareStatement(handler, ms.getStatementLog());
      //StatementHandler.query
      return handler.query(stmt, resultHandler);
    } finally {
      closeStatement(stmt);
    }
  }

  @Override
  public List<BatchResult> doFlushStatements(boolean isRollback) {
	//doFlushStatements只是给BatchExecutor用的,所以这里返回空(返回null更好了)
    return Collections.emptyList();
  }

  /**
   * 通过数据库连接创建Statement
   * @param handler
   * @param statementLog
   * @return
   * @throws SQLException
   */
  private Statement prepareStatement(StatementHandler handler, Log statementLog) throws SQLException {
    Statement stmt;
    // 1、获得数据库连接
    Connection connection = getConnection(statementLog);
    // 2、生成Statement  (jdbc也是这么干的)
    stmt = handler.prepare(connection);
    // 3、参数化 (SimpleStatementHandler啥也没干)
    handler.parameterize(stmt);
    // 4、返回Statement
    return stmt;
  }

}
