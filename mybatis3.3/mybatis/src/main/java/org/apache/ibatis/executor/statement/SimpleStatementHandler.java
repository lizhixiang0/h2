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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.keygen.Jdbc3KeyGenerator;
import org.apache.ibatis.executor.keygen.KeyGenerator;
import org.apache.ibatis.executor.keygen.SelectKeyGenerator;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

/**
 * 简单语句处理器(STATEMENT)
 * 直接使用普通的Statement对象，这样每次执行SQL语句都需要数据库对SQL进行预编译
 * 设置：
 *    在编写sql语句时指定statementType,默认使用SimpleStatementHandler
 *    <insert id="save"  statementType="STATEMENT"><!-- STATEMENT,PREPARED 或CALLABLE -->
 * @author Clinton Begin
 */
public class SimpleStatementHandler extends BaseStatementHandler {

  public SimpleStatementHandler(Executor executor, MappedStatement mappedStatement, Object parameter, RowBounds rowBounds, ResultHandler resultHandler, BoundSql boundSql) {
    super(executor, mappedStatement, parameter, rowBounds, resultHandler, boundSql);
  }

  @Override
  public int update(Statement statement) throws SQLException {
    // 1、获得sql
    String sql = boundSql.getSql();
    // 2、获得参数对象
    Object parameterObject = boundSql.getParameterObject();
    // 3、获得键值生成器
    KeyGenerator keyGenerator = mappedStatement.getKeyGenerator();
    // 4、用于返回更新数目
    int rows;
    if (keyGenerator instanceof Jdbc3KeyGenerator) {
      // a1、执行sql,返回自增主键 (前提表中Id必须是自增长的)
      statement.execute(sql, Statement.RETURN_GENERATED_KEYS);
      // b1、获得影响行数
      rows = statement.getUpdateCount();
      // c1、将主键赋值到参数对象中去
      keyGenerator.processAfter(executor, mappedStatement, statement, parameterObject);
    } else if (keyGenerator instanceof SelectKeyGenerator) {
      // a2、执行sql (生成BaseStatementHandler时会尝试获取主键,如果用户设置的executeBefore,那么主键此时已经在参数对象中了)
      statement.execute(sql);
      // c2、获得影响行数
      rows = statement.getUpdateCount();
      // c3、如果用户设置的executeAfter,那么此时还得去执行一次sql获得主键 (所以我们到底要不要使用这个呢?或者是什么时候使用这个呢？)
      keyGenerator.processAfter(executor, mappedStatement, statement, parameterObject);
    } else {
      //如果没有keyGenerator,直接调用Statement.execute和Statement.getUpdateCount,此时参数对象里是没有主键值的
      statement.execute(sql);
      rows = statement.getUpdateCount();
    }
    return rows;
  }

  @Override
  public void batch(Statement statement) throws SQLException {
    String sql = boundSql.getSql();
    // 将给定的SQL命令添加到此Statement对象的当前命令列表中。通过调用方法 executeBatch 可以批量执行此列表中的命令
    statement.addBatch(sql);
  }

  /**
   * select-->结果给ResultHandler
   * @param statement
   * @param resultHandler
   * @param <E>
   * @return
   * @throws SQLException
   */
  @Override
  public <E> List<E> query(Statement statement, ResultHandler resultHandler) throws SQLException {
    String sql = boundSql.getSql();
    statement.execute(sql);
    // 先执行Statement.execute,然后交给ResultSetHandler.handleResultSets
    return resultSetHandler.handleResultSets(statement);
  }

  /**
   * 创建Statement (调用Connection.createStatement)
   * @param connection
   * @throws SQLException
   */
  @Override
  protected Statement instantiateStatement(Connection connection) throws SQLException {
    if (mappedStatement.getResultSetType() != null) {
      // 如果结果集类型不为null,则按要求创建对应的Statement  (ResultSet.CONCUR_READ_ONLY表示只读,即对结果集的操作不影响数据库)
      return connection.createStatement(mappedStatement.getResultSetType().getValue(), ResultSet.CONCUR_READ_ONLY);
    } else {
      return connection.createStatement();
    }
  }

  @Override
  public void parameterize(Statement statement) {
  }

}
