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

import java.sql.SQLException;
import java.util.List;

import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.transaction.Transaction;

/**
 * 执行器
 * @author Clinton Begin
 */
public interface Executor {

  /**
   * 表示不需要ResultHandler
   */
  ResultHandler NO_RESULT_HANDLER = null;

  /**
   *
   * @param ms  映射的sql语句
   * @param parameter  参数
   */
  int update(MappedStatement ms, Object parameter) throws SQLException;

  /**
   * 查询 ,缓存查询
   * @param ms 映射的sql语句
   * @param parameter 参数
   * @param rowBounds 分页
   * @param resultHandler 结果处理器
   * @param cacheKey 缓存key
   * @param boundSql  ？？？
   */
  <E> List<E> query(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler, CacheKey cacheKey, BoundSql boundSql) throws SQLException;

  /**
   * 查询
   * @param ms 映射的sql语句
   * @param parameter 参数
   * @param rowBounds 分页
   * @param resultHandler 结果处理器
   */
  <E> List<E> query(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler) throws SQLException;

  /**
   * 刷新批处理语句
   */
  List<BatchResult> flushStatements() throws SQLException;

  /**
   * 创建CacheKey
   * @param ms 映射的sql语句
   * @param parameterObject 参数
   * @param rowBounds  分页
   * @param boundSql  ？？？
   * @return
   */
  CacheKey createCacheKey(MappedStatement ms, Object parameterObject, RowBounds rowBounds, BoundSql boundSql);

  /**
   * 判断是否缓存
   * @param ms 映射的sql语句
   * @param key 缓存key
   * @return
   */
  boolean isCached(MappedStatement ms, CacheKey key);

  /**
   * 清理session缓存
   */
  void clearLocalCache();

  /**
   * 延迟加载
   * @param ms   嵌套的sql映射语句
   * @param resultObject  ??
   * @param property  ??
   * @param key  缓存key
   * @param targetType ??
   */
  void deferLoad(MappedStatement ms, MetaObject resultObject, String property, CacheKey key, Class<?> targetType);

  /**
   * 获取事务管理器
   * @return
   */
  Transaction getTransaction();

  /**
   * 提交，参数表示是否要强制
   */
  void commit(boolean required) throws SQLException;

  /**
   * 回滚，参数表示是否要强制
   */
  void rollback(boolean required) throws SQLException;

  /**
   * 关闭连接
   * @param forceRollback
   */
  void close(boolean forceRollback);

  /**
   * ??
   * @return
   */
  boolean isClosed();

  /**
   * 设置执行器包装器
   * @param executor
   */
  void setExecutorWrapper(Executor executor);

}
