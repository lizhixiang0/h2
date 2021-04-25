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
package org.apache.ibatis.session.defaults;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.binding.BindingException;
import org.apache.ibatis.exceptions.ExceptionFactory;
import org.apache.ibatis.exceptions.TooManyResultsException;
import org.apache.ibatis.executor.BatchResult;
import org.apache.ibatis.executor.ErrorContext;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.result.DefaultMapResultHandler;
import org.apache.ibatis.executor.result.DefaultResultContext;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.SqlSession;

/**
 * mybatis提供的默认SqlSession实现
 * @author Clinton Begin
 * @note 为什么说DefaultSqlSession不是线程安全的？
 */
public class DefaultSqlSession implements SqlSession {
  /**
   * 核心配置类
   */
  private Configuration configuration;
  /**
   * 执行器,一般为SimpleExecutor
   */
  private Executor executor;

  /**
   * 是否自动提交（一般是关闭的自动提交的,因为要使用事务）
   */
  private boolean autoCommit;
  /**
   * 有没有产生脏数据 （如果关闭了自动提交,则进行了数据的增删改则会产生脏数据，此时需要强制commit或强制rollback）
   */
  private boolean dirty;

  /**
   * 构造函数初始化
   * @param configuration
   * @param executor
   * @param autoCommit
   */
  public DefaultSqlSession(Configuration configuration, Executor executor, boolean autoCommit) {
    this.configuration = configuration;
    this.executor = executor;
    this.dirty = false;
    this.autoCommit = autoCommit;
  }

  public DefaultSqlSession(Configuration configuration, Executor executor) {
    this(configuration, executor, false);
  }

  @Override
  public <T> T selectOne(String statement) {
    return this.selectOne(statement, null);
  }

  /**
   * 1、核心selectOne
   */
  @Override
  public <T> T selectOne(String statement, Object parameter) {
    // 1、转而去调用selectList
    List<T> list = this.selectList(statement, parameter);
    // 1.1、得到1条则返回1条
    if (list.size() == 1) {
      return list.get(0);
    } else if (list.size() > 1) {
      // 1.2、 得到多条报TooManyResultsException错
      throw new TooManyResultsException("Expected one result (or null) to be returned by selectOne(), but found: " + list.size());
    } else {
      // 1.3、 如果得到0条则返回null,即当没有查询到结果的时候就会返回null (因此建议resultType=包装类型而不是基本类型)
      return null;
    }
  }

  @Override
  public <K, V> Map<K, V> selectMap(String statement, String mapKey) {
    return this.selectMap(statement, null, mapKey, RowBounds.DEFAULT);
  }

  @Override
  public <K, V> Map<K, V> selectMap(String statement, Object parameter, String mapKey) {
    return this.selectMap(statement, parameter, mapKey, RowBounds.DEFAULT);
  }

  /**
   * 2、核心selectMap
   */
  @Override
  public <K, V> Map<K, V> selectMap(String statement, Object parameter, String mapKey, RowBounds rowBounds) {
    // 1、转而去调用selectList
    final List<?> list = selectList(statement, parameter, rowBounds);
    // 2、创建DefaultMapResultHandler
    final DefaultMapResultHandler<K, V> mapResultHandler = new DefaultMapResultHandler<>(mapKey,configuration.getObjectFactory(), configuration.getObjectWrapperFactory());
    // 3、创建DefaultResultContext
    final DefaultResultContext context = new DefaultResultContext();
    // 4、循环用DefaultMapResultHandler处理每条记录
    for (Object o : list) {
      context.nextResultObject(o);
      mapResultHandler.handleResult(context);
    }
    // 5、返回所有已处理的记录(一个Map)
    return mapResultHandler.getMappedResults();
  }

  @Override
  public <E> List<E> selectList(String statement) {
    return this.selectList(statement, null);
  }

  @Override
  public <E> List<E> selectList(String statement, Object parameter) {
    return this.selectList(statement, parameter, RowBounds.DEFAULT);
  }

  /**
   * 3、核心selectList
   */
  @Override
  public <E> List<E> selectList(String statement, Object parameter, RowBounds rowBounds) {
    try {
      // 1、根据statement id找到对应的MappedStatement
      MappedStatement ms = configuration.getMappedStatement(statement);
      // 2、转而用执行器来查询结果（这里的ResultHandler是null)
      return executor.query(ms, wrapCollection(parameter), rowBounds, Executor.NO_RESULT_HANDLER);
    } catch (Exception e) {
      throw ExceptionFactory.wrapException("Error querying database.  Cause: " + e, e);
    } finally {
      ErrorContext.instance().reset();
    }
  }

  @Override
  public void select(String statement, Object parameter, ResultHandler handler) {
    select(statement, parameter, RowBounds.DEFAULT, handler);
  }

  @Override
  public void select(String statement, ResultHandler handler) {
    select(statement, null, RowBounds.DEFAULT, handler);
  }

  /**
   * 4、核心select,和selectList代码差不多的，区别就是多了个ResultHandler
   */
  @Override
  public void select(String statement, Object parameter, RowBounds rowBounds, ResultHandler handler) {
    try {
      MappedStatement ms = configuration.getMappedStatement(statement);
      executor.query(ms, wrapCollection(parameter), rowBounds, handler);
    } catch (Exception e) {
      throw ExceptionFactory.wrapException("Error querying database.  Cause: " + e, e);
    } finally {
      ErrorContext.instance().reset();
    }
  }

  @Override
  public int insert(String statement) {
    return insert(statement, null);
  }

  /**
   * 5、核心insert
   * @return
   */
  @Override
  public int insert(String statement, Object parameter) {
    // 调用update
    return update(statement, parameter);
  }

  /**
   * 6、核心delete
   */
  @Override
  public int delete(String statement) {
    //调用update
    return update(statement, null);
  }

  @Override
  public int delete(String statement, Object parameter) {
    return update(statement, parameter);
  }

  @Override
  public int update(String statement) {
    return update(statement, null);
  }

  /**
   * 7、核心update
   */
  @Override
  public int update(String statement, Object parameter) {
    try {
      // 每次要更新之前，dirty标志设为true
      dirty = true;
      MappedStatement ms = configuration.getMappedStatement(statement);
      return executor.update(ms, wrapCollection(parameter));
    } catch (Exception e) {
      throw ExceptionFactory.wrapException("Error updating database.  Cause: " + e, e);
    } finally {
      ErrorContext.instance().reset();
    }
  }

  @Override
  public void commit() {
    commit(false);
  }

  /**
   *  8、核心commit
   * @param force 是否强制commit
   */
  @Override
  public void commit(boolean force) {
    try {
      executor.commit(isCommitOrRollbackRequired(force));
      // 每次commit之后，dirty标志设为false
      dirty = false;
    } catch (Exception e) {
      throw ExceptionFactory.wrapException("Error committing transaction.  Cause: " + e, e);
    } finally {
      ErrorContext.instance().reset();
    }
  }

  @Override
  public void rollback() {
    rollback(false);
  }

  /**
   * 9、核心rollback
   * @param force 是否强制rollback
   */
  @Override
  public void rollback(boolean force) {
    try {
      executor.rollback(isCommitOrRollbackRequired(force));
      //每次rollback之后，dirty标志设为false
      dirty = false;
    } catch (Exception e) {
      throw ExceptionFactory.wrapException("Error rolling back transaction.  Cause: " + e, e);
    } finally {
      ErrorContext.instance().reset();
    }
  }

  /**
   * 10、核心flushStatements
   *  ？？？
   */
  @Override
  public List<BatchResult> flushStatements() {
    try {
      return executor.flushStatements();
    } catch (Exception e) {
      throw ExceptionFactory.wrapException("Error flushing statements.  Cause: " + e, e);
    } finally {
      ErrorContext.instance().reset();
    }
  }

  /**
   * 11、核心close
   */
  @Override
  public void close() {
    try {
      executor.close(isCommitOrRollbackRequired(false));
      // 每次close之后,dirty标志设为false
      dirty = false;
    } finally {
      ErrorContext.instance().reset();
    }
  }

  @Override
  public Configuration getConfiguration() {
    return configuration;
  }

  /**
   * 根据dao接口类，获取映射代理类对象
   * PersonDao personDao =  sqlSession.getMapper(PersonDao.class);
   */
  @Override
  public <T> T getMapper(Class<T> type) {
    // 最后会去调用MapperRegistry.getMapper
    return configuration.getMapper(type, this);
  }

  @Override
  public Connection getConnection() {
    try {
      return executor.getTransaction().getConnection();
    } catch (SQLException e) {
      throw ExceptionFactory.wrapException("Error getting a new connection.  Cause: " + e, e);
    }
  }

  /**
   * 12、核心clearCache,用执行器来clearLocalCache
   */
  @Override
  public void clearCache() {
    executor.clearLocalCache();
  }

  /**
   * 检查是否需要强制commit或rollback
   * 两种情况返回true
   *     1、关闭了自动提交且产生了脏数据
   *     2、调用者强制要求
   * @param force
   * @return
   */
  private boolean isCommitOrRollbackRequired(boolean force) {
    return (!autoCommit && dirty) || force;
  }

  /**
   * 把参数包装成Collection
   * @note 参数加final的用处：使得入参在调用方法内部不能被修改 https://blog.csdn.net/qq_43059674/article/details/87907163
   */
  private Object wrapCollection(final Object object) {
    if (object instanceof Collection) {
      // a、参数若是Collection型,做collection标记
      StrictMap<Object> map = new StrictMap<>();
      map.put("collection", object);
      if (object instanceof List) {
        // a1、参数若是List型，再做list标记
        map.put("list", object);
      }
      // a2、返回map
      return map;
    } else if (object != null && object.getClass().isArray()) {
      // b、参数若是数组型,做array标记
      StrictMap<Object> map = new StrictMap<>();
      map.put("array", object);
      // b1、返回map
      return map;
    }
    // c、参数若不是集合型，直接返回原来值
    return object;
  }

  /**
   * 严格的Map,如果找不到对应的key，直接抛BindingException例外，而不是返回null
   * @param <V>
   */
  public static class StrictMap<V> extends HashMap<String, V> {

    private static final long serialVersionUID = -5741767162221585340L;

    @Override
    public V get(Object key) {
      if (!super.containsKey(key)) {
        throw new BindingException("Parameter '" + key + "' not found. Available parameters are " + this.keySet());
      }
      return super.get(key);
    }

  }

}
