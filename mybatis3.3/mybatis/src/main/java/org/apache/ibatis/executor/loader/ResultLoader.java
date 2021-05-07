/*
 *    Copyright 2009-2013 the original author or authors.
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
package org.apache.ibatis.executor.loader;

import java.sql.SQLException;
import java.util.List;

import javax.sql.DataSource;

import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.ExecutorException;
import org.apache.ibatis.executor.ResultExtractor;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ExecutorType;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.transaction.Transaction;
import org.apache.ibatis.transaction.TransactionFactory;

/**
 * 内置sql加载器，有的结果映射属性配置了内置的sql,这种情况用到这个类
 * @author Clinton Begin
 */
public class ResultLoader {

  protected final Configuration configuration;
  protected final MappedStatement mappedStatement;
  protected final Object parameterObject;
  protected final Class<?> targetType;
  protected final ObjectFactory objectFactory;
  protected final CacheKey cacheKey;
  protected final BoundSql boundSql;
  /**
   * 结果提取器
   */
  protected final ResultExtractor resultExtractor;
  /**
   * 记录当前线程id
   */
  protected final long creatorThreadId;

  /**
   * 执行器,构造ResultLoader是会传递一个执行器
   */
  protected final Executor executor;

  protected boolean loaded;

  protected Object resultObject;

  public ResultLoader(Configuration config, Executor executor, MappedStatement mappedStatement, Object parameterObject, Class<?> targetType, CacheKey cacheKey, BoundSql boundSql) {
    // 全局配置类
    this.configuration = config;
    // 执行器
    this.executor = executor;
    // sql
    this.mappedStatement = mappedStatement;
    // sql参数
    this.parameterObject = parameterObject;
    // 目标类型
    this.targetType = targetType;
    // 对象构建工厂
    this.objectFactory = configuration.getObjectFactory();
    // 缓存key
    this.cacheKey = cacheKey;
    // sql
    this.boundSql = boundSql;
    // 结果提取器
    this.resultExtractor = new ResultExtractor(configuration, objectFactory);
    // 线程标记值
    this.creatorThreadId = Thread.currentThread().getId();
  }

  /**
   * 核心方法：执行sql,加载结果
   */
  public Object loadResult() throws SQLException {
	// 1.执行sql,得到list集合
    List<Object> list = selectList();
    // 2.使用结果提取器.将list集合提取成目标类型
    resultObject = resultExtractor.extractObjectFromList(list, targetType);
    // 3、返回目标结果
    return resultObject;
  }

  private <E> List<E> selectList() throws SQLException {
    Executor localExecutor = executor;
    // 1、如果外面传递进来的executor已经关闭了，则创建一个新的
    if (Thread.currentThread().getId() != this.creatorThreadId || localExecutor.isClosed()) {
      localExecutor = newExecutor();
    }
    try {
      // 2、执行query
      return localExecutor.query(mappedStatement, parameterObject, RowBounds.DEFAULT, Executor.NO_RESULT_HANDLER, cacheKey, boundSql);
    } finally {
      // 3、如果不是外面传递进来的,则用完关闭
      if (localExecutor != executor) {
        localExecutor.close(false);
      }
    }
  }

  /**
   * 创建简单执行器
   * @return
   */
  private Executor newExecutor() {
    final Environment environment = configuration.getEnvironment();
    if (environment == null) {
      throw new ExecutorException("ResultLoader could not load lazily.  Environment was not configured.");
    }
    final DataSource ds = environment.getDataSource();
    if (ds == null) {
      throw new ExecutorException("ResultLoader could not load lazily.  DataSource was not configured.");
    }
    final TransactionFactory transactionFactory = environment.getTransactionFactory();
    final Transaction tx = transactionFactory.newTransaction(ds, null, false);
    // 默认创建一个新的SimpleExecutor
    return configuration.newExecutor(tx, ExecutorType.SIMPLE);
  }

  public boolean wasNull() {
    return resultObject == null;
  }

}
