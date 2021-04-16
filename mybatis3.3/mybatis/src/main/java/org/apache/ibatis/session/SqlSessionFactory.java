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
package org.apache.ibatis.session;

import java.sql.Connection;

/**
 * SqlSession工厂,创建SqlSession
 * @author Clinton Begin
 */
public interface SqlSessionFactory {
  /**
   * 1、最普通的
   */
  SqlSession openSession();

  /**
   * 2、配置是否自动提交
   * @param autoCommit
   * @return
   */
  SqlSession openSession(boolean autoCommit);

  /**
   * 3、配置数据库连接
   * @param connection 数据库连接
   * @return
   */
  SqlSession openSession(Connection connection);

  /**
   * 4、配置事务隔离级别
   * @param level 事务隔离级别
   */
  SqlSession openSession(TransactionIsolationLevel level);

  SqlSession openSession(ExecutorType execType);
  SqlSession openSession(ExecutorType execType, boolean autoCommit);
  SqlSession openSession(ExecutorType execType, TransactionIsolationLevel level);
  SqlSession openSession(ExecutorType execType, Connection connection);

  Configuration getConfiguration();

}
