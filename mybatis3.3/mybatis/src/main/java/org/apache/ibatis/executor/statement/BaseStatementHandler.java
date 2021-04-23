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

import org.apache.ibatis.executor.ErrorContext;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.ExecutorException;
import org.apache.ibatis.executor.keygen.KeyGenerator;
import org.apache.ibatis.executor.parameter.ParameterHandler;
import org.apache.ibatis.executor.resultset.ResultSetHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.type.TypeHandlerRegistry;

/**
 * 语句处理器的基类
 * @author Clinton Begin
 */
public abstract class BaseStatementHandler implements StatementHandler {

  protected final Configuration configuration;
  protected final Executor executor;
  protected final MappedStatement mappedStatement;
  protected final RowBounds rowBounds;
  protected final TypeHandlerRegistry typeHandlerRegistry;
  protected final ObjectFactory objectFactory;
  protected BoundSql boundSql;
  protected final ResultSetHandler resultSetHandler;
  protected final ParameterHandler parameterHandler;



  protected BaseStatementHandler(Executor executor, MappedStatement mappedStatement, Object parameterObject, RowBounds rowBounds, ResultHandler resultHandler, BoundSql boundSql) {
    this.configuration = mappedStatement.getConfiguration();
    this.executor = executor;
    this.mappedStatement = mappedStatement;
    this.rowBounds = rowBounds;
    this.typeHandlerRegistry = configuration.getTypeHandlerRegistry();
    this.objectFactory = configuration.getObjectFactory();
    // 1、如果boundSql为null则生成
    if (boundSql == null) {
      generateKeys(parameterObject);
      boundSql = mappedStatement.getBoundSql(parameterObject);
    }
    this.boundSql = boundSql;
    // 2、生成parameterHandler
    this.parameterHandler = configuration.newParameterHandler(mappedStatement, parameterObject, boundSql);
    // 3、生成resultSetHandler
    this.resultSetHandler = configuration.newResultSetHandler(executor, mappedStatement, rowBounds, parameterHandler, resultHandler, boundSql);
  }

  @Override
  public BoundSql getBoundSql() {
    return boundSql;
  }

  @Override
  public ParameterHandler getParameterHandler() {
    return parameterHandler;
  }

  /**
   * 准备语句
   * @param connection
   * @return statement
   */
  @Override
  public Statement prepare(Connection connection) throws SQLException {
    ErrorContext.instance().sql(boundSql.getSql());
    Statement statement = null;
    try {
      // 1、实例化Statement
      statement = instantiateStatement(connection);
      // 2、设置超时
      setStatementTimeout(statement);
      // 3、设置读取的限制条数
      setFetchSize(statement);
      // 4、返回
      return statement;
    } catch (SQLException e) {
      closeStatement(statement);
      throw e;
    } catch (Exception e) {
      closeStatement(statement);
      throw new ExecutorException("Error preparing statement.  Cause: " + e, e);
    }
  }

  /**
   * 如何实例化Statement，交给子类实现
   */
  protected abstract Statement instantiateStatement(Connection connection) throws SQLException;

  /**
   * 设置超时,其实就是调用Statement.setQueryTimeout
   * @param stmt
   * @throws SQLException
   */
  protected void setStatementTimeout(Statement stmt) throws SQLException {
    // 1、读出sql映射语句中的超时设置
    Integer timeout = mappedStatement.getTimeout();
    // 2、读出核心配置类中的默认超时设置
    Integer defaultTimeout = configuration.getDefaultStatementTimeout();
    // 3、优先存sql映射语句的超时设置
    if (timeout != null) {
      stmt.setQueryTimeout(timeout);
    } else if (defaultTimeout != null) {
      stmt.setQueryTimeout(defaultTimeout);
    }
  }

  /**
   * 设置读取条数  （如果没设置）
   * @param stmt
   * @throws SQLException
   */
  protected void setFetchSize(Statement stmt) throws SQLException {
    Integer fetchSize = mappedStatement.getFetchSize();
    if (fetchSize != null) {
      stmt.setFetchSize(fetchSize);
    }
  }

  //关闭语句
  protected void closeStatement(Statement statement) {
    try {
      if (statement != null) {
        statement.close();
      }
    } catch (SQLException e) {
      //ignore
    }
  }

  /**
   * 生成主键
   * @param parameter
   */
  protected void generateKeys(Object parameter) {
    // 1、取的KeyGenerator对象,一般我们使用Jdbc3KeyGenerator
    KeyGenerator keyGenerator = mappedStatement.getKeyGenerator();
    // 2、将线程日志收起来,防止被污染,然后执行完processBefore再召回
    ErrorContext.instance().store();
    // 3、执行processBefore (Jdbc3KeyGenerator的这个方法啥也不干,SelectKeyGenerator会将主键值查出然后赋值给parameter)
    keyGenerator.processBefore(executor, mappedStatement, null, parameter);
    ErrorContext.instance().recall();
  }

}
