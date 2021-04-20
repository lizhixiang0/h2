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

import static org.apache.ibatis.executor.ExecutionPlaceholder.EXECUTION_PLACEHOLDER;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.cache.impl.PerpetualCache;
import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;
import org.apache.ibatis.logging.jdbc.ConnectionLogger;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.mapping.ParameterMode;
import org.apache.ibatis.mapping.StatementType;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.LocalCacheScope;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.transaction.Transaction;
import org.apache.ibatis.type.TypeHandlerRegistry;

/**
 * 执行器基类
 * @author Clinton Begin
 */
public abstract class BaseExecutor implements Executor {
  private static final Log log = LogFactory.getLog(BaseExecutor.class);

  protected Transaction transaction;
  /**
   * 延迟加载队列容器
   */
  protected ConcurrentLinkedQueue<DeferredLoad> deferredLoads;
  /**
   * 本地缓存容器
   */
  protected PerpetualCache localCache;
  /**
   * 存储OUT参数 （存储过程专用）
   */
  protected PerpetualCache localOutputParameterCache;
  /**
   * 执行器是否关闭的标识,未关闭方能执行相关方法
   */
  private boolean closed;
  protected Configuration configuration;
  protected Executor wrapper;
  /**
   * 查询堆栈
   */
  protected int queryStack = 0;

  /**
   * 抽象类的构造函数用来属性初始化
   */
  protected BaseExecutor(Configuration configuration, Transaction transaction) {
    // 核心配置类
    this.configuration = configuration;
    // 事务管理器
    this.transaction = transaction;
    // 1、创建线程安全的延迟加载队列容器
    this.deferredLoads = new ConcurrentLinkedQueue<>();
    // 2、创建本地缓存容器 （据说能防止循环引用（circular references）和加速重复嵌套查询(一级缓存))
    this.localCache = new PerpetualCache("LocalCache");
    // 3、创建本地输出参数缓存容器
    this.localOutputParameterCache = new PerpetualCache("LocalOutputParameterCache");
    // 4、初始化closed
    this.closed = false;
    // 5、初始化wrapper
    this.wrapper = this;
  }

  @Override
  public Transaction getTransaction() {
    if (closed) {
      throw new ExecutorException("Executor was closed.");
    }
    return transaction;
  }

  @Override
  public void close(boolean forceRollback) {
    try {
      try {
        // 1、关闭之前先执行rollback （清空本地缓存并回滚远程数据库）
        rollback(forceRollback);
      } finally {
        if (transaction != null) {
          // 5、最后才执行close
          transaction.close();
        }
      }
    } catch (SQLException e) {
      log.warn("Unexpected exception on closing transaction.  Cause: " + e);
    } finally {
      // 3、出异常了将引用设值为null,方便垃圾回收
      transaction = null;
      deferredLoads = null;
      localCache = null;
      localOutputParameterCache = null;
      // 4、执行器标识设值为close
      closed = true;
    }
  }

  @Override
  public boolean isClosed() {
    return closed;
  }

  /**
   * SqlSession.update/insert/delete会调用此方法
   */
  @Override
  public int update(MappedStatement ms, Object parameter) throws SQLException {
    // 1、添加异常上下文信息
    ErrorContext.instance().resource(ms.getResource()).activity("executing an update").object(ms.getId());
    if (closed) {
      throw new ExecutorException("Executor was closed.");
    }
    // 2、先清局部缓存
    clearLocalCache();
    // 3、执行更新，如何更新交由子类，模板方法模式(回调函数)
    return doUpdate(ms, parameter);
  }

  /**
   * 刷新语句,BatchExecutor调用
   */
  @Override
  public List<BatchResult> flushStatements() throws SQLException {
    return flushStatements(false);
  }

  /**
   * 起到一种预插入的作用
   * @note
   * @link "https://blog.csdn.net/y41992910/article/details/53641825
   */
  public List<BatchResult> flushStatements(boolean isRollBack) throws SQLException {
    if (closed) {
      throw new ExecutorException("Executor was closed.");
    }
    return doFlushStatements(isRollBack);
  }

  /**
   * SqlSession.selectList会调用此方法
   * @param ms 映射的sql语句
   * @param parameter 参数
   * @param rowBounds 分页
   * @param resultHandler 结果处理器
   */
  @Override
  public <E> List<E> query(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler) throws SQLException {
    // 1、得到绑定sql
    BoundSql boundSql = ms.getBoundSql(parameter);
    // 2、创建缓存Key
    CacheKey key = createCacheKey(ms, parameter, rowBounds, boundSql);
    // 3、查询
    return query(ms, parameter, rowBounds, resultHandler, key, boundSql);
 }

  @SuppressWarnings("unchecked")
  @Override
  public <E> List<E> query(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler, CacheKey key, BoundSql boundSql) throws SQLException {
    ErrorContext.instance().resource(ms.getResource()).activity("executing a query").object(ms.getId());
    // 1、如果已经关闭，报错
    if (closed) {
      throw new ExecutorException("Executor was closed.");
    }
    // 2、当前没有其他用户查询且sql语句为增删改,则清空缓存
    if (queryStack == 0 && ms.isFlushCacheRequired()) {
      clearLocalCache();
    }
    List<E> list;
    try {
      // 3、查询堆+1
      queryStack++;
      // 4、如果resultHandler为null,则根据CacheKey从localCache去查
      list = resultHandler == null ? (List<E>) localCache.getObject(key) : null;
      if (list != null) {
        // 5、若查到localCache缓存,则处理下parameter对象
        handleLocallyCachedOutputParameters(ms, key, parameter, boundSql);
      } else {
        // 6、查不到从数据库查
        list = queryFromDatabase(ms, parameter, rowBounds, resultHandler, key, boundSql);
      }
    } finally {
      // 7、查询堆-1
      queryStack--;
    }
    if (queryStack == 0) {
      // 8、延迟加载队列中所有元素
      for (DeferredLoad deferredLoad : deferredLoads) {
        deferredLoad.load();
      }
      // 9、清空延迟加载队列
      deferredLoads.clear();
      if (configuration.getLocalCacheScope() == LocalCacheScope.STATEMENT) {
        // 10、如果是STATEMENT,情空本地缓存
        clearLocalCache();
      }
    }
    // 11、返回查询结果
    return list;
  }

  /**
   * 延迟加载，DefaultResultSetHandler.getNestedQueryMappingValue调用.属于嵌套查询，比较高级.
   * @param ms   映射的sql语句
   * @param resultObject  ??
   * @param property  ??
   * @param key  缓存key
   * @param targetType ??
   */
  @Override
  public void deferLoad(MappedStatement ms, MetaObject resultObject, String property, CacheKey key, Class<?> targetType) {
    if (closed) {
      throw new ExecutorException("Executor was closed.");
    }
    DeferredLoad deferredLoad = new DeferredLoad(resultObject, property, key, localCache, configuration, targetType);
    //如果能加载，则立刻加载，否则加入到延迟加载队列中
    if (deferredLoad.canLoad()) {
      deferredLoad.load();
    } else {
      //这里怎么又new了一个新的，性能有点问题
      deferredLoads.add(new DeferredLoad(resultObject, property, key, localCache, configuration, targetType));
    }
  }

  /**
   * 创建缓存Key
   * MyBatis 对于其 Key 的生成采取规则为：[MappedStatementId + offset + limit + SQL + queryParams + environment]生成一个哈希码
   * @param ms 映射的sql语句
   * @param parameterObject 参数
   * @param rowBounds  分页
   * @param boundSql  绑定sql
   * @return
   */
  @Override
  public CacheKey createCacheKey(MappedStatement ms, Object parameterObject, RowBounds rowBounds, BoundSql boundSql) {
    if (closed) {
      throw new ExecutorException("Executor was closed.");
    }
    // 1、创建CacheKey,然后设置部分属性
    CacheKey cacheKey = new CacheKey();
    cacheKey.update(ms.getId());
    cacheKey.update(Integer.valueOf(rowBounds.getOffset()));
    cacheKey.update(Integer.valueOf(rowBounds.getLimit()));
    cacheKey.update(boundSql.getSql());
    // 2、获取参数映射集合
    List<ParameterMapping> parameterMappings = boundSql.getParameterMappings();
    // 3、获取类型处理器注册表
    TypeHandlerRegistry typeHandlerRegistry = ms.getConfiguration().getTypeHandlerRegistry();
    // 4、循环遍历参数映射集合
    for (int i = 0; i < parameterMappings.size(); i++) {
      // a、取出参数映射对象
      ParameterMapping parameterMapping = parameterMappings.get(i);
      // b、只有不是输出模式参数才进行处理
      if (parameterMapping.getMode() != ParameterMode.OUT) {
        Object value;
        // I、取出属性名
        String propertyName = parameterMapping.getProperty();
        // II、查看boundSql中有没有该属性对应的属性值
        if (boundSql.hasAdditionalParameter(propertyName)) {
          value = boundSql.getAdditionalParameter(propertyName);
        } else if (parameterObject == null) {
          value = null;
        } else if (typeHandlerRegistry.hasTypeHandler(parameterObject.getClass())) {
          value = parameterObject;
        } else {
          MetaObject metaObject = configuration.newMetaObject(parameterObject);
          value = metaObject.getValue(propertyName);
        }
        // .. 设置属性值
        cacheKey.update(value);
      }
    }
    if (configuration.getEnvironment() != null) {
      // 5、配置环境ID
      cacheKey.update(configuration.getEnvironment().getId());
    }
    // 6、返回cacheKey
    return cacheKey;
  }

  @Override
  public boolean isCached(MappedStatement ms, CacheKey key) {
    return localCache.getObject(key) != null;
  }

  @Override
  public void commit(boolean required) throws SQLException {
    if (closed) {
      throw new ExecutorException("Cannot commit, transaction is already closed");
    }
    clearLocalCache();
    flushStatements();
    if (required) {
      transaction.commit();
    }
  }

  @Override
  public void rollback(boolean required) throws SQLException {
    if (!closed) {
      try {
        // 1、清空缓存
        clearLocalCache();
        // 2、没有啥作用,还容易引起歧义
        flushStatements(true);
      } finally {
        if (required) {
          // 3、判断是否需要强制回滚(执行增删改)，如果是，则远程数据库回滚
          transaction.rollback();
        }
      }
    }
  }

  @Override
  public void clearLocalCache() {
    if (!closed) {
      // 1、清空本地缓存
      localCache.clear();
      // 2、清空本地参数缓存
      localOutputParameterCache.clear();
    }
  }

  protected abstract int doUpdate(MappedStatement ms, Object parameter) throws SQLException;

  protected abstract List<BatchResult> doFlushStatements(boolean isRollback) throws SQLException;

  //query-->queryFromDatabase-->doQuery
  protected abstract <E> List<E> doQuery(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler, BoundSql boundSql) throws SQLException;

  protected void closeStatement(Statement statement) {
    if (statement != null) {
      try {
        statement.close();
      } catch (SQLException e) {
        // ignore
      }
    }
  }

  /**
   * 针对存储过程,如果是输出类型,则需要将缓存中的数据赋值给parameter
   */
  private void handleLocallyCachedOutputParameters(MappedStatement ms, CacheKey key, Object parameter, BoundSql boundSql) {
    // 1、首先判断是不是存储过程
    if (ms.getStatementType() == StatementType.CALLABLE) {
      // 2、如果是存储过程,从输出参数缓存容器中拿到该参数对象
      final Object cachedParameter = localOutputParameterCache.getObject(key);
      // 3、若该缓存对象是否不为null,则进一步处理
      if (cachedParameter != null && parameter != null) {
        final MetaObject metaCachedParameter = configuration.newMetaObject(cachedParameter);
        final MetaObject metaParameter = configuration.newMetaObject(parameter);
        // 3、循环遍历该sql的参数映射
        for (ParameterMapping parameterMapping : boundSql.getParameterMappings()) {
          // 如果某个参数映射不是IN类型的,则将该参数从缓存中拿出来，赋值给参数对象 （因为在使用存储过程时,ON和INOUT类型会改变传入的参数）
          if (parameterMapping.getMode() != ParameterMode.IN) {
            final String parameterName = parameterMapping.getProperty();
            final Object cachedValue = metaCachedParameter.getValue(parameterName);
            metaParameter.setValue(parameterName, cachedValue);
          }
        }
      }
    }
  }

  /**
   * 从数据库查数据
   * @throws SQLException
   */
  private <E> List<E> queryFromDatabase(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler, CacheKey key, BoundSql boundSql) throws SQLException {
    List<E> list;
    // 1、先存把key存入localCache,此时value随便是啥(MyBatis搞了个占位符对象,不晓得这样的好处是啥,直接搞null不行吗)
    localCache.putObject(key, EXECUTION_PLACEHOLDER);
    try {
      // 2、执行doQuery,回调函数
      list = doQuery(ms, parameter, rowBounds, resultHandler, boundSql);
    } finally {
      // 3、最后删除占位符
      localCache.removeObject(key);
    }
    // 4、加入缓存
    localCache.putObject(key, list);
    // 5、如果是存储过程,将参数存入localOutputParameterCache,作用是记录OUT参数的变化
    if (ms.getStatementType() == StatementType.CALLABLE) {
      localOutputParameterCache.putObject(key, parameter);
    }
    return list;
  }

  /**
   * 生成可以打印日志的数据库连接 （代理模式）
   * @param statementLog
   * @return
   * @throws SQLException
   */
  protected Connection getConnection(Log statementLog) throws SQLException {
    Connection connection = transaction.getConnection();
    if (statementLog.isDebugEnabled()) {
      return ConnectionLogger.newInstance(connection, statementLog, queryStack);
    } else {
      return connection;
    }
  }

  @Override
  public void setExecutorWrapper(Executor wrapper) {
    this.wrapper = wrapper;
  }

  /**
   * 静态内部类：延迟加载
   */
  private static class DeferredLoad {

    private final MetaObject resultObject;
    private final String property;
    private final Class<?> targetType;
    private final CacheKey key;
    private final PerpetualCache localCache;
    private final ObjectFactory objectFactory;
    private final ResultExtractor resultExtractor;

    public DeferredLoad(MetaObject resultObject, String property, CacheKey key, PerpetualCache localCache, Configuration configuration, Class<?> targetType) {
      this.resultObject = resultObject;
      this.property = property;
      this.key = key;
      this.localCache = localCache;
      this.objectFactory = configuration.getObjectFactory();
      this.resultExtractor = new ResultExtractor(configuration, objectFactory);
      this.targetType = targetType;
    }

    /**
     * 缓存中找到，且不为占位符，代表可以加载
     */
    public boolean canLoad() {
      return localCache.getObject(key) != null && localCache.getObject(key) != EXECUTION_PLACEHOLDER;
    }

    /**
     * 加载
     */
    public void load() {
      @SuppressWarnings( "unchecked" )
      // 我们假设我们得到了一个列表
      List<Object> list = (List<Object>) localCache.getObject(key);
      // 调用ResultExtractor.extractObjectFromList
      Object value = resultExtractor.extractObjectFromList(list, targetType);
      resultObject.setValue(property, value);
    }

  }

}
