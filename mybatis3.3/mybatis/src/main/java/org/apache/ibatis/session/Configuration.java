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
package org.apache.ibatis.session;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import org.apache.ibatis.binding.MapperRegistry;
import org.apache.ibatis.builder.CacheRefResolver;
import org.apache.ibatis.builder.ResultMapResolver;
import org.apache.ibatis.builder.annotation.MethodResolver;
import org.apache.ibatis.builder.xml.XMLStatementBuilder;
import org.apache.ibatis.cache.Cache;
import org.apache.ibatis.cache.decorators.FifoCache;
import org.apache.ibatis.cache.decorators.LruCache;
import org.apache.ibatis.cache.decorators.SoftCache;
import org.apache.ibatis.cache.decorators.WeakCache;
import org.apache.ibatis.cache.impl.PerpetualCache;
import org.apache.ibatis.datasource.jndi.JndiDataSourceFactory;
import org.apache.ibatis.datasource.pooled.PooledDataSourceFactory;
import org.apache.ibatis.datasource.unpooled.UnpooledDataSourceFactory;
import org.apache.ibatis.executor.BatchExecutor;
import org.apache.ibatis.executor.CachingExecutor;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.ReuseExecutor;
import org.apache.ibatis.executor.SimpleExecutor;
import org.apache.ibatis.executor.keygen.KeyGenerator;
import org.apache.ibatis.executor.loader.ProxyFactory;
import org.apache.ibatis.executor.loader.cglib.CglibProxyFactory;
import org.apache.ibatis.executor.loader.javassist.JavassistProxyFactory;
import org.apache.ibatis.executor.parameter.ParameterHandler;
import org.apache.ibatis.executor.resultset.DefaultResultSetHandler;
import org.apache.ibatis.executor.resultset.ResultSetHandler;
import org.apache.ibatis.executor.statement.RoutingStatementHandler;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;
import org.apache.ibatis.logging.commons.JakartaCommonsLoggingImpl;
import org.apache.ibatis.logging.jdk14.Jdk14LoggingImpl;
import org.apache.ibatis.logging.log4j.Log4jImpl;
import org.apache.ibatis.logging.log4j2.Log4j2Impl;
import org.apache.ibatis.logging.nologging.NoLoggingImpl;
import org.apache.ibatis.logging.slf4j.Slf4jImpl;
import org.apache.ibatis.logging.stdout.StdOutImpl;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ParameterMap;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.mapping.VendorDatabaseIdProvider;
import org.apache.ibatis.parsing.XNode;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.InterceptorChain;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.factory.DefaultObjectFactory;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.reflection.wrapper.DefaultObjectWrapperFactory;
import org.apache.ibatis.reflection.wrapper.ObjectWrapperFactory;
import org.apache.ibatis.scripting.LanguageDriver;
import org.apache.ibatis.scripting.LanguageDriverRegistry;
import org.apache.ibatis.scripting.defaults.RawLanguageDriver;
import org.apache.ibatis.scripting.xmltags.XMLLanguageDriver;
import org.apache.ibatis.transaction.Transaction;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.apache.ibatis.transaction.managed.ManagedTransactionFactory;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeAliasRegistry;
import org.apache.ibatis.type.TypeHandlerRegistry;

/**
 * Configuration配置类
 * @author Clinton Begin
 */
@Getter
@Setter
public class Configuration {

  /**
   *  1、环境变量
   */
  protected Environment environment;
  public Configuration(Environment environment) {
    this();
    this.environment = environment;
  }

  /**
   *  2、允许在嵌套语句中使用分页（RowBounds）。如果允许使用则设置为false。 todo 没懂啥意思
   */
  protected boolean safeRowBoundsEnabled = false;


  /**
   *  3、是否允许在嵌套语句中使用结果处理器（ResultHandler）。如果允许使用则设置为 false  todo
   */
  protected boolean safeResultHandlerEnabled = true;

  /**
   *  4、驼峰转换  设为true表示开启
   * 作用:可以将数据库中user_name转化成userName与实体类属性对应,配置后无需写resultMapper将数据库字段和实体类属性对应
   */
  protected boolean mapUnderscoreToCamelCase = false;

  /**
   * 5、懒加载  默认为false
   *
   *  lazyLoadingEnabled属性启用时只要加载对象，就会加载该对象的所有属性
   * @blog "https://www.cnblogs.com/ashleyboy/p/9286814.html
   *       "https://blog.csdn.net/weixin_42476601/article/details/84194210
   */
  protected boolean lazyLoadingEnabled = false;

  /**
   * 6、积极的懒加载 ，默认为true ,配合lazyLoadingEnabled使用
   *    如果aggressiveLazyLoading=true，只要触发到对象任何的方法，就会立即加载所有属性的加载
   */
  protected boolean aggressiveLazyLoading = true;

  /**
   *  6、指定调用对象的哪些方法前触发一次数据加载
   *  保证我们的目标方法被调用时延迟加载的对象已经从数据库中加载出来了
   * @blog "https://www.jb51.net/article/101885.htm
   */
  protected Set<String> lazyLoadTriggerMethods = new HashSet<>(Arrays.asList("equals", "clone", "hashCode", "toString"));

  /**
   *  7、是否允许单一语句返回多结果集（需要兼容驱动）。todo
   * @blog "https://blog.csdn.net/qq_40233503/article/details/94436578
   */
  protected boolean multipleResultSetsEnabled = true;

  /**
   *  8、调用JDBC的getGeneratedKeys方法获取主键然后赋值到keyProperty设置的领域模型属性（一般为id）中。 如果允许使用则设置为 true
   * @example1 <setting name="useGeneratedKeys" value="true" />
   * @example2 <insert id="insert" parameterType="jw.base.entity.WrongRecApply" useGeneratedKeys="true" keyProperty="id" ></insert>
   * @blog "https://www.cnblogs.com/nuccch/p/9069644.html
   */
  protected boolean useGeneratedKeys = false;

  /**
   * 9、使用列标签代替列别名 允许使用则设置为 true
   * @note 列标签就是数据库中的字段名，列别名就是查询语句查询字段的时候给字段自定义的名称
   */
  protected boolean useColumnLabel = true;

  /**
   * 10、当结果集中某字段为null值时是否执行映射。true为执行  。此设置只对resultType为集合类型有效
   * @blog "https://www.cnblogs.com/Oliver-rebirth/p/mybatis_2018-3-24.html
   * @use "https://www.cnblogs.com/shamo89/p/7807955.html
   *      "https://www.cnblogs.com/libin6505/p/10036898.html
   */
  protected boolean callSettersOnNulls = false;

  /**
   *  11、设置日志   这个logPrefix不知道啥用 todo
   * @blog "https://www.cnblogs.com/junlinsky/p/12810752.html
   */
  protected String logPrefix;
  protected Class <? extends Log> logImpl;
  public Class<? extends Log> getLogImpl() {
    return logImpl;
  }
  @SuppressWarnings("unchecked")
  public void setLogImpl(Class<?> logImpl) {
    if (logImpl != null) {
      this.logImpl = (Class<? extends Log>) logImpl;
      LogFactory.useCustomLogging(this.logImpl);
    }
  }

  /**
   *  12、一级缓存机制配置   默认SESSION
   * @blog 理解一级缓存的SESSION级别和STATEMENT级别  "https://www.jianshu.com/p/c553169c5921
   * @note 在query方法执行的最后，会判断一级缓存级别是否是STATEMENT级别，如果是的话，清空缓存,这样就避免了出现脏数据！
   *
   */
  protected LocalCacheScope localCacheScope = LocalCacheScope.SESSION;

  /**
   * 13、二级缓存设置 默认值为true
   * @blog Mybatis 如何配置二级缓存 ？ "https://blog.csdn.net/canot/article/details/51491732
   * @blog Mybatis 为什么不推荐用二级缓存？ "https://www.cnblogs.com/KingIceMou/p/9389872.html   todo
   */
  protected boolean cacheEnabled = true;

  /**
   *  14、当没有为参数提供特定的 JDBC 类型时，为空值指定 JDBC 类型。
   *     某些驱动需要指定列的 JDBC 类型，例如oracle数据库需配置JdbcType.NULL
   * @blog "https://blog.csdn.net/weixin_42447959/article/details/105006410
   * @note 但是我在使用时发现对于mysql这玩意似乎可有可无  todo
   */
  protected JdbcType jdbcTypeForNull = JdbcType.OTHER;

  /**
   *  15、设置查询超时时间，不设置则无线等待  todo
   *  如果是一些sql执行时间需要超过defaultStatementTimeout,可以通过Mapper文件单独的sql的timeout进行配置的。
   */
  protected Integer defaultStatementTimeout;

  /**
   * 16、MyBatis可以根据不同的数据库厂商执行不同的语句，用于一个系统内多厂商数据源支持。大部分场景下无需修改 todo
   */
  protected String databaseId;

  /**
   * 17、配置文件中所有<property>的属性名及属性值
   * 例如：<property name="username" value="dev_user"/>
   */
  protected Properties variables = new Properties();

  /**
   * 18、设置执行器,默认为简单执行器,todo
   * @blog "https://www.cnblogs.com/zhaoyan001/p/10905826.html
   * @blog "https://segmentfault.com/a/1190000022800141
   */
  protected ExecutorType defaultExecutorType = ExecutorType.SIMPLE;

  /**
   * 19、自动映射全局配置
   * @blog "https://www.jb51.net/article/198342.htm
   * @note mybatis中自动映射主要有2种配置，
   *       一种是全局的配置，对应用中所有的resultMap起效，这个是在mybatis配置文件中进行设置的；
   *       另外一种是通过resultMap的autoMapping属性进行配置
   */
  protected AutoMappingBehavior autoMappingBehavior = AutoMappingBehavior.PARTIAL;

  /**
   * 20、对象工厂,mybatis提供了默认实现,支持定制化
   */
  protected ObjectFactory objectFactory = new DefaultObjectFactory();
  /**
   * 21、包装器工厂,mybatis提供了默认实现,支持定制化
   */
  protected ObjectWrapperFactory objectWrapperFactory = new DefaultObjectWrapperFactory();

  /**
   * 22、创建元对象,弄啥嘞？
   *
   */
  public MetaObject newMetaObject(Object object) {
    return MetaObject.forObject(object, objectFactory, objectWrapperFactory);
  }
  /**
   * 映射注册机
   */
  protected MapperRegistry mapperRegistry = new MapperRegistry(this);
  /**
   * 代理工厂,Using internal Javassist instead of OGNL
   */
  protected ProxyFactory proxyFactory = new JavassistProxyFactory();

  /**
   * 配置类工厂,Used to create Configuration for loading deserialized unread properties.
   * @see <a href='https://code.google.com/p/mybatis/issues/detail?id=300'>Issue 300</a> (google code)
   */
  protected Class<?> configurationFactory;

  protected final InterceptorChain interceptorChain = new InterceptorChain();
  //类型处理器注册机
  protected final TypeHandlerRegistry typeHandlerRegistry = new TypeHandlerRegistry();
  //类型别名注册机
  protected final TypeAliasRegistry typeAliasRegistry = new TypeAliasRegistry();
  protected final LanguageDriverRegistry languageRegistry = new LanguageDriverRegistry();

  //映射的语句,存在Map里
  protected final Map<String, MappedStatement> mappedStatements = new StrictMap<MappedStatement>("Mapped Statements collection");
  //缓存,存在Map里
  protected final Map<String, Cache> caches = new StrictMap<Cache>("Caches collection");
  //结果映射,存在Map里
  protected final Map<String, ResultMap> resultMaps = new StrictMap<ResultMap>("Result Maps collection");
  protected final Map<String, ParameterMap> parameterMaps = new StrictMap<ParameterMap>("Parameter Maps collection");
  protected final Map<String, KeyGenerator> keyGenerators = new StrictMap<KeyGenerator>("Key Generators collection");

  protected final Set<String> loadedResources = new HashSet<String>();
  protected final Map<String, XNode> sqlFragments = new StrictMap<XNode>("XML fragments parsed from previous mappers");

  //不完整的SQL语句
  protected final Collection<XMLStatementBuilder> incompleteStatements = new LinkedList<XMLStatementBuilder>();
  protected final Collection<CacheRefResolver> incompleteCacheRefs = new LinkedList<CacheRefResolver>();
  protected final Collection<ResultMapResolver> incompleteResultMaps = new LinkedList<ResultMapResolver>();
  protected final Collection<MethodResolver> incompleteMethods = new LinkedList<MethodResolver>();

  /**
   * A map holds cache-ref relationship. The key is the namespace that
   * references a cache bound to another namespace and the value is the
   * namespace which the actual cache is bound to.
   */
  protected final Map<String, String> cacheRefMap = new HashMap<String, String>();

  public Configuration() {
    //注册更多的类型别名，至于为何不直接在TypeAliasRegistry里注册，还需进一步研究
    typeAliasRegistry.registerAlias("JDBC", JdbcTransactionFactory.class);
    typeAliasRegistry.registerAlias("MANAGED", ManagedTransactionFactory.class);
    typeAliasRegistry.registerAlias("JNDI", JndiDataSourceFactory.class);
    typeAliasRegistry.registerAlias("POOLED", PooledDataSourceFactory.class);
    typeAliasRegistry.registerAlias("UNPOOLED", UnpooledDataSourceFactory.class);
    typeAliasRegistry.registerAlias("PERPETUAL", PerpetualCache.class);
    typeAliasRegistry.registerAlias("FIFO", FifoCache.class);
    typeAliasRegistry.registerAlias("LRU", LruCache.class);
    typeAliasRegistry.registerAlias("SOFT", SoftCache.class);
    typeAliasRegistry.registerAlias("WEAK", WeakCache.class);
    typeAliasRegistry.registerAlias("DB_VENDOR", VendorDatabaseIdProvider.class);
    typeAliasRegistry.registerAlias("XML", XMLLanguageDriver.class);
    typeAliasRegistry.registerAlias("RAW", RawLanguageDriver.class);
    typeAliasRegistry.registerAlias("SLF4J", Slf4jImpl.class);
    typeAliasRegistry.registerAlias("COMMONS_LOGGING", JakartaCommonsLoggingImpl.class);
    typeAliasRegistry.registerAlias("LOG4J", Log4jImpl.class);
    typeAliasRegistry.registerAlias("LOG4J2", Log4j2Impl.class);
    typeAliasRegistry.registerAlias("JDK_LOGGING", Jdk14LoggingImpl.class);
    typeAliasRegistry.registerAlias("STDOUT_LOGGING", StdOutImpl.class);
    typeAliasRegistry.registerAlias("NO_LOGGING", NoLoggingImpl.class);
    typeAliasRegistry.registerAlias("CGLIB", CglibProxyFactory.class);
    typeAliasRegistry.registerAlias("JAVASSIST", JavassistProxyFactory.class);

    languageRegistry.setDefaultDriverClass(XMLLanguageDriver.class);
    languageRegistry.register(RawLanguageDriver.class);
  }

  public void addLoadedResource(String resource) {
    loadedResources.add(resource);
  }

  public boolean isResourceLoaded(String resource) {
    return loadedResources.contains(resource);
  }


  public void setProxyFactory(ProxyFactory proxyFactory) {
    if (proxyFactory == null) {
      proxyFactory = new JavassistProxyFactory();
    }
    this.proxyFactory = proxyFactory;
  }

  /**
   * @since 3.2.2
   */
  public List<Interceptor> getInterceptors() {
    return interceptorChain.getInterceptors();
  }

  public void setDefaultScriptingLanguage(Class<?> driver) {
    if (driver == null) {
      driver = XMLLanguageDriver.class;
    }
    getLanguageRegistry().setDefaultDriverClass(driver);
  }

  public LanguageDriver getDefaultScriptingLanuageInstance() {
    return languageRegistry.getDefaultDriver();
  }

  //创建参数处理器
  public ParameterHandler newParameterHandler(MappedStatement mappedStatement, Object parameterObject, BoundSql boundSql) {
    //创建ParameterHandler
    ParameterHandler parameterHandler = mappedStatement.getLang().createParameterHandler(mappedStatement, parameterObject, boundSql);
    //插件在这里插入
    parameterHandler = (ParameterHandler) interceptorChain.pluginAll(parameterHandler);
    return parameterHandler;
  }

  //创建结果集处理器
  public ResultSetHandler newResultSetHandler(Executor executor, MappedStatement mappedStatement, RowBounds rowBounds, ParameterHandler parameterHandler,
      ResultHandler resultHandler, BoundSql boundSql) {
    //创建DefaultResultSetHandler(稍老一点的版本3.1是创建NestedResultSetHandler或者FastResultSetHandler)
    ResultSetHandler resultSetHandler = new DefaultResultSetHandler(executor, mappedStatement, parameterHandler, resultHandler, boundSql, rowBounds);
    //插件在这里插入
    resultSetHandler = (ResultSetHandler) interceptorChain.pluginAll(resultSetHandler);
    return resultSetHandler;
  }

  //创建语句处理器
  public StatementHandler newStatementHandler(Executor executor, MappedStatement mappedStatement, Object parameterObject, RowBounds rowBounds, ResultHandler resultHandler, BoundSql boundSql) {
    //创建路由选择语句处理器
    StatementHandler statementHandler = new RoutingStatementHandler(executor, mappedStatement, parameterObject, rowBounds, resultHandler, boundSql);
    //插件在这里插入
    statementHandler = (StatementHandler) interceptorChain.pluginAll(statementHandler);
    return statementHandler;
  }

  public Executor newExecutor(Transaction transaction) {
    return newExecutor(transaction, defaultExecutorType);
  }

  //产生执行器
  public Executor newExecutor(Transaction transaction, ExecutorType executorType) {
    executorType = executorType == null ? defaultExecutorType : executorType;
    //这句再做一下保护,囧,防止粗心大意的人将defaultExecutorType设成null?
    executorType = executorType == null ? ExecutorType.SIMPLE : executorType;
    Executor executor;
    //然后就是简单的3个分支，产生3种执行器BatchExecutor/ReuseExecutor/SimpleExecutor
    if (ExecutorType.BATCH == executorType) {
      executor = new BatchExecutor(this, transaction);
    } else if (ExecutorType.REUSE == executorType) {
      executor = new ReuseExecutor(this, transaction);
    } else {
      executor = new SimpleExecutor(this, transaction);
    }
    //如果要求缓存，生成另一种CachingExecutor(默认就是有缓存),装饰者模式,所以默认都是返回CachingExecutor
    if (cacheEnabled) {
      executor = new CachingExecutor(executor);
    }
    //此处调用插件,通过插件可以改变Executor行为
    executor = (Executor) interceptorChain.pluginAll(executor);
    return executor;
  }

  public void addKeyGenerator(String id, KeyGenerator keyGenerator) {
    keyGenerators.put(id, keyGenerator);
  }

  public Collection<String> getKeyGeneratorNames() {
    return keyGenerators.keySet();
  }

  public Collection<KeyGenerator> getKeyGenerators() {
    return keyGenerators.values();
  }

  public KeyGenerator getKeyGenerator(String id) {
    return keyGenerators.get(id);
  }

  public boolean hasKeyGenerator(String id) {
    return keyGenerators.containsKey(id);
  }

  public void addCache(Cache cache) {
    caches.put(cache.getId(), cache);
  }

  public Collection<String> getCacheNames() {
    return caches.keySet();
  }

  public Collection<Cache> getCaches() {
    return caches.values();
  }

  public Cache getCache(String id) {
    return caches.get(id);
  }

  public boolean hasCache(String id) {
    return caches.containsKey(id);
  }

  public void addResultMap(ResultMap rm) {
    resultMaps.put(rm.getId(), rm);
    checkLocallyForDiscriminatedNestedResultMaps(rm);
    checkGloballyForDiscriminatedNestedResultMaps(rm);
  }

  public Collection<String> getResultMapNames() {
    return resultMaps.keySet();
  }

  public Collection<ResultMap> getResultMaps() {
    return resultMaps.values();
  }

  public ResultMap getResultMap(String id) {
    return resultMaps.get(id);
  }

  public boolean hasResultMap(String id) {
    return resultMaps.containsKey(id);
  }

  public void addParameterMap(ParameterMap pm) {
    parameterMaps.put(pm.getId(), pm);
  }

  public Collection<String> getParameterMapNames() {
    return parameterMaps.keySet();
  }

  public Collection<ParameterMap> getParameterMaps() {
    return parameterMaps.values();
  }

  public ParameterMap getParameterMap(String id) {
    return parameterMaps.get(id);
  }

  public boolean hasParameterMap(String id) {
    return parameterMaps.containsKey(id);
  }

  public void addMappedStatement(MappedStatement ms) {
    mappedStatements.put(ms.getId(), ms);
  }

  public Collection<String> getMappedStatementNames() {
    buildAllStatements();
    return mappedStatements.keySet();
  }

  public Collection<MappedStatement> getMappedStatements() {
    buildAllStatements();
    return mappedStatements.values();
  }

  public Collection<XMLStatementBuilder> getIncompleteStatements() {
    return incompleteStatements;
  }

  public void addIncompleteStatement(XMLStatementBuilder incompleteStatement) {
    incompleteStatements.add(incompleteStatement);
  }

  public Collection<CacheRefResolver> getIncompleteCacheRefs() {
    return incompleteCacheRefs;
  }

  public void addIncompleteCacheRef(CacheRefResolver incompleteCacheRef) {
    incompleteCacheRefs.add(incompleteCacheRef);
  }

  public Collection<ResultMapResolver> getIncompleteResultMaps() {
    return incompleteResultMaps;
  }

  public void addIncompleteResultMap(ResultMapResolver resultMapResolver) {
    incompleteResultMaps.add(resultMapResolver);
  }

  public void addIncompleteMethod(MethodResolver builder) {
    incompleteMethods.add(builder);
  }

  public Collection<MethodResolver> getIncompleteMethods() {
    return incompleteMethods;
  }

  //由DefaultSqlSession.selectList调用过来
  public MappedStatement getMappedStatement(String id) {
    return this.getMappedStatement(id, true);
  }

  public MappedStatement getMappedStatement(String id, boolean validateIncompleteStatements) {
    //先构建所有语句，再返回语句
    if (validateIncompleteStatements) {
      buildAllStatements();
    }
    return mappedStatements.get(id);
  }

  public Map<String, XNode> getSqlFragments() {
    return sqlFragments;
  }

  public void addInterceptor(Interceptor interceptor) {
    interceptorChain.addInterceptor(interceptor);
  }

  //将包下所有类加入到mapper
  public void addMappers(String packageName, Class<?> superType) {
    mapperRegistry.addMappers(packageName, superType);
  }

  public void addMappers(String packageName) {
    mapperRegistry.addMappers(packageName);
  }

  public <T> void addMapper(Class<T> type) {
    mapperRegistry.addMapper(type);
  }

  public <T> T getMapper(Class<T> type, SqlSession sqlSession) {
    return mapperRegistry.getMapper(type, sqlSession);
  }

  public boolean hasMapper(Class<?> type) {
    return mapperRegistry.hasMapper(type);
  }

  public boolean hasStatement(String statementName) {
    return hasStatement(statementName, true);
  }

  public boolean hasStatement(String statementName, boolean validateIncompleteStatements) {
    if (validateIncompleteStatements) {
      buildAllStatements();
    }
    return mappedStatements.containsKey(statementName);
  }

  public void addCacheRef(String namespace, String referencedNamespace) {
    cacheRefMap.put(namespace, referencedNamespace);
  }

  /**
   * Parses all the unprocessed statement nodes in the cache. It is recommended
   * to call this method once all the mappers are added as it provides fail-fast
   * statement validation.
   */
  protected void buildAllStatements() {
    if (!incompleteResultMaps.isEmpty()) {
      synchronized (incompleteResultMaps) {
        // This always throws a BuilderException.
        incompleteResultMaps.iterator().next().resolve();
      }
    }
    if (!incompleteCacheRefs.isEmpty()) {
      synchronized (incompleteCacheRefs) {
        // This always throws a BuilderException.
        incompleteCacheRefs.iterator().next().resolveCacheRef();
      }
    }
    if (!incompleteStatements.isEmpty()) {
      synchronized (incompleteStatements) {
        // This always throws a BuilderException.
        incompleteStatements.iterator().next().parseStatementNode();
      }
    }
    if (!incompleteMethods.isEmpty()) {
      synchronized (incompleteMethods) {
        // This always throws a BuilderException.
        incompleteMethods.iterator().next().resolve();
      }
    }
  }

  /**
   * Extracts namespace from fully qualified statement id.
   *
   * @param statementId
   * @return namespace or null when id does not contain period.
   */
  protected String extractNamespace(String statementId) {
    int lastPeriod = statementId.lastIndexOf('.');
    return lastPeriod > 0 ? statementId.substring(0, lastPeriod) : null;
  }

  // Slow but a one time cost. A better solution is welcome.
  protected void checkGloballyForDiscriminatedNestedResultMaps(ResultMap rm) {
    if (rm.hasNestedResultMaps()) {
      for (Map.Entry<String, ResultMap> entry : resultMaps.entrySet()) {
        Object value = entry.getValue();
        if (value instanceof ResultMap) {
          ResultMap entryResultMap = (ResultMap) value;
          if (!entryResultMap.hasNestedResultMaps() && entryResultMap.getDiscriminator() != null) {
            Collection<String> discriminatedResultMapNames = entryResultMap.getDiscriminator().getDiscriminatorMap().values();
            if (discriminatedResultMapNames.contains(rm.getId())) {
              entryResultMap.forceNestedResultMaps();
            }
          }
        }
      }
    }
  }

  // Slow but a one time cost. A better solution is welcome.
  protected void checkLocallyForDiscriminatedNestedResultMaps(ResultMap rm) {
    if (!rm.hasNestedResultMaps() && rm.getDiscriminator() != null) {
      for (Map.Entry<String, String> entry : rm.getDiscriminator().getDiscriminatorMap().entrySet()) {
        String discriminatedResultMapName = entry.getValue();
        if (hasResultMap(discriminatedResultMapName)) {
          ResultMap discriminatedResultMap = resultMaps.get(discriminatedResultMapName);
          if (discriminatedResultMap.hasNestedResultMaps()) {
            rm.forceNestedResultMaps();
            break;
          }
        }
      }
    }
  }

  //静态内部类,严格的Map，不允许多次覆盖key所对应的value
  protected static class StrictMap<V> extends HashMap<String, V> {

    private static final long serialVersionUID = -4950446264854982944L;
    private String name;

    public StrictMap(String name, int initialCapacity, float loadFactor) {
      super(initialCapacity, loadFactor);
      this.name = name;
    }

    public StrictMap(String name, int initialCapacity) {
      super(initialCapacity);
      this.name = name;
    }

    public StrictMap(String name) {
      super();
      this.name = name;
    }

    public StrictMap(String name, Map<String, ? extends V> m) {
      super(m);
      this.name = name;
    }

    @SuppressWarnings("unchecked")
    public V put(String key, V value) {
      if (containsKey(key)) {
        //如果已经存在此key了，直接报错
        throw new IllegalArgumentException(name + " already contains value for " + key);
      }
      if (key.contains(".")) {
        //如果有.符号，取得短名称，大致用意就是包名不同，类名相同，提供模糊查询的功能
        final String shortKey = getShortName(key);
        if (super.get(shortKey) == null) {
          //如果没有这个缩略，则放一个缩略
          super.put(shortKey, value);
        } else {
          //如果已经有此缩略，表示模糊，放一个Ambiguity型的
          super.put(shortKey, (V) new Ambiguity(shortKey));
        }
      }
      //再放一个全名
      return super.put(key, value);
      //可以看到，如果有包名，会放2个key到这个map，一个缩略，一个全名
    }

    @Override
    public V get(Object key) {
      V value = super.get(key);
      //如果找不到相应的key，直接报错
      if (value == null) {
        throw new IllegalArgumentException(name + " does not contain value for " + key);
      }
      //如果是模糊型的，也报错，提示用户
      //原来这个模糊型就是为了提示用户啊
      if (value instanceof Ambiguity) {
        throw new IllegalArgumentException(((Ambiguity) value).getSubject() + " is ambiguous in " + name
            + " (try using the full name including the namespace, or rename one of the entries)");
      }
      return value;
    }

    //取得短名称，也就是取得最后那个句号的后面那部分
    private String getShortName(String key) {
      final String[] keyparts = key.split("\\.");
      return keyparts[keyparts.length - 1];
    }

    //模糊，居然放在Map里面的一个静态内部类，
    protected static class Ambiguity {
      //提供一个主题
      private String subject;

      public Ambiguity(String subject) {
        this.subject = subject;
      }

      public String getSubject() {
        return subject;
      }
    }
  }

}
