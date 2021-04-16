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
package org.apache.ibatis.transaction.managed;

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;
import org.apache.ibatis.session.TransactionIsolationLevel;
import org.apache.ibatis.transaction.Transaction;

/**
 * 委托性事务管理器,交给容器(比如 Spring 或 JEE 应用服务器的上下文)来管理事务的整个生命周期
 * @author Clinton Begin
 */
public class ManagedTransaction implements Transaction {

  private static final Log log = LogFactory.getLog(ManagedTransaction.class);

  private Connection connection;
  private DataSource dataSource;
  private TransactionIsolationLevel level;
  // 是否关闭数据库连接
  private boolean closeConnection;

  /**
   * @param connection 数据库连接
   * @param closeConnection 是否关闭连接
   */
  public ManagedTransaction(Connection connection, boolean closeConnection) {
    this.connection = connection;
    this.closeConnection = closeConnection;
  }

  public ManagedTransaction(DataSource ds, TransactionIsolationLevel level, boolean closeConnection) {
    this.dataSource = ds;
    this.level = level;
    this.closeConnection = closeConnection;
  }

  @Override
  public Connection getConnection() throws SQLException {
    if (this.connection == null) {
      openConnection();
    }
    return this.connection;
  }

  @Override
  public void commit() throws SQLException {
    // 托管事务commit和rollback都是不做事的，交给容器管理
  }

  @Override
  public void rollback() throws SQLException {
    // do nothing
  }

  @Override
  public void close() throws SQLException {
    // 如果closeConnection为true,那说明connection已经是关闭的,不需要再去关闭
    if (this.closeConnection && this.connection != null) {
      if (log.isDebugEnabled()) {
        log.debug("Closing JDBC Connection [" + this.connection + "]");
      }
      this.connection.close();
    }
  }

  protected void openConnection() throws SQLException {
    if (log.isDebugEnabled()) {
      log.debug("Opening JDBC Connection");
    }
    // 1、建立连接
    this.connection = this.dataSource.getConnection();
    if (this.level != null) {
      // 2、设置隔离级别
      this.connection.setTransactionIsolation(this.level.getLevel());
      // 3、默认是自动提交，这一步交给容器来处理
    }
  }

}
