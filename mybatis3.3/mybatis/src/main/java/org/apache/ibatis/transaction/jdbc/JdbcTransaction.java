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
package org.apache.ibatis.transaction.jdbc;

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;
import org.apache.ibatis.session.TransactionIsolationLevel;
import org.apache.ibatis.transaction.Transaction;
import org.apache.ibatis.transaction.TransactionException;

/**
 * 使用JDBC的事务管理机制,就是利用java.sql.Connection对象完成对事务的管理
 * 注意:
 *    1、自动提交时忽略提交或回滚请求
 *    2、mybatis自动为我们开启了事务，并且设置为不自动提交事务。
 *      所以如果不手动提交(sqlSession.commit())，事务会自动回滚，无法对数据库中的数据进行增删改
 *
 * @author admin
 */
public class JdbcTransaction implements Transaction {

  private static final Log log = LogFactory.getLog(JdbcTransaction.class);

  protected Connection connection;
  protected DataSource dataSource;
  protected TransactionIsolationLevel level;

  protected boolean autoCommit;

  /**
   * 构造函数一
   * @param ds 数据源
   * @param desiredLevel 隔离级别
   * @param desiredAutoCommit 是否自动提交
   */
  public JdbcTransaction(DataSource ds, TransactionIsolationLevel desiredLevel, boolean desiredAutoCommit) {
    dataSource = ds;
    level = desiredLevel;
    autoCommit = desiredAutoCommit;
  }

  /**
   *  构造函数二
   * @param connection 数据库连接   只传递数据库连接代表什么？？使用默认的数据库连接吗？？
   */
  public JdbcTransaction(Connection connection) {
    this.connection = connection;
  }


  @Override
  public Connection getConnection() throws SQLException {
    if (connection == null) {
      // 如果没有传递数据库连接进来,就自己建立连接
      openConnection();
    }
    return connection;
  }

  protected void openConnection() throws SQLException {
    if (log.isDebugEnabled()) {
      log.debug("Opening JDBC Connection");
    }
    // 1、建立连接
    connection = dataSource.getConnection();
    if (level != null) {
      // 2、设置隔离级别
      connection.setTransactionIsolation(level.getLevel());
    }
    // 3、用户选择是否自动提交
    setDesiredAutoCommit(autoCommit);
  }

  protected void setDesiredAutoCommit(boolean desiredAutoCommit) {
    try {
      // mysql默认是自动提交,所以这里可以判断一下
      if (connection.getAutoCommit() != desiredAutoCommit) {
        if (log.isDebugEnabled()) {
          log.debug("Setting autocommit to " + desiredAutoCommit + " on JDBC Connection [" + connection + "]");
        }
        connection.setAutoCommit(desiredAutoCommit);
      }
    } catch (SQLException e) {
      throw new TransactionException("Error configuring AutoCommit.  "+ "Your driver may not support getAutoCommit() or setAutoCommit(). "+ "Requested setting: " + desiredAutoCommit + ".  Cause: " + e, e);
    }
  }

  @Override
  public void commit() throws SQLException {
    // 1、自动提交时忽略提交请求
    if (connection != null && !connection.getAutoCommit()) {
      if (log.isDebugEnabled()) {
        log.debug("Committing JDBC Connection [" + connection + "]");
      }
      // 2、如果不是,手动提交
      connection.commit();
    }
  }

  @Override
  public void rollback() throws SQLException {
    // 1、自动提交时忽略回滚请求
    if (connection != null && !connection.getAutoCommit()) {
      if (log.isDebugEnabled()) {
        log.debug("Rolling back JDBC Connection [" + connection + "]");
      }
      // 2、如果不是,手动提交。如果是自动提交,他自己都提交了，回滚有个锤子用。
      connection.rollback();
    }
  }

  @Override
  public void close() throws SQLException {
    if (connection != null) {
      // 关闭数据库连接之前将自动提交设为true
      resetAutoCommit();
      if (log.isDebugEnabled()) {
        log.debug("Closing JDBC Connection [" + connection + "]");
      }
      // 关闭连接
      connection.close();
    }
  }

  /**
   * 如果只执行select语句，MyBatis不会在数据库连接上调用commit/rollback。但有些数据库用select语句也会开始事务,然后它们要求必须在关闭连接之前进行提交/回滚。
   * MyBatis提供了一种解决方案是在关闭连接之前将自动提交设置为true。
   */
  protected void resetAutoCommit() {
    try {
      if (!connection.getAutoCommit()) {
        if (log.isDebugEnabled()) {
          log.debug("Resetting autocommit to true on JDBC Connection [" + connection + "]");
        }
        connection.setAutoCommit(true);
      }
    } catch (SQLException e) {
      log.debug("Error resetting autocommit to true "+ "before closing the connection.  Cause: " + e);
    }
  }

}
