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
package org.apache.ibatis.builder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.ibatis.cache.Cache;
import org.apache.ibatis.cache.decorators.LruCache;
import org.apache.ibatis.cache.impl.PerpetualCache;
import org.apache.ibatis.executor.ErrorContext;
import org.apache.ibatis.executor.keygen.KeyGenerator;
import org.apache.ibatis.mapping.CacheBuilder;
import org.apache.ibatis.mapping.Discriminator;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ParameterMap;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.mapping.ParameterMode;
import org.apache.ibatis.mapping.ResultFlag;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.mapping.ResultMapping;
import org.apache.ibatis.mapping.ResultSetType;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.mapping.StatementType;
import org.apache.ibatis.reflection.MetaClass;
import org.apache.ibatis.scripting.LanguageDriver;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeHandler;

/**
 * 映射构建器助手,一个XML映射解析器对应一个
 * @author Clinton Begin
 */
public class MapperBuilderAssistant extends BaseBuilder {
  /**
   * 命名空间（接口全限定名）
   */
  private String currentNamespace;
  /**
   * 资源路径 （xml映射文件）
   */
  private String resource;
  /**
   * 表示当前xml的缓存
   */
  private Cache currentCache;
  /**
   * CacheRef是否解析完
   */
  private boolean unresolvedCacheRef;

  public MapperBuilderAssistant(Configuration configuration, String resource) {
    super(configuration);
    ErrorContext.instance().resource(resource);
    this.resource = resource;
  }

  public String getCurrentNamespace() {
    return currentNamespace;
  }

  public void setCurrentNamespace(String currentNamespace) {
    if (currentNamespace == null) {
      throw new BuilderException("The mapper element requires a namespace attribute to be specified.");
    }
    if (this.currentNamespace != null && !this.currentNamespace.equals(currentNamespace)) {
      throw new BuilderException("Wrong namespace. Expected '"+ this.currentNamespace + "' but found '" + currentNamespace + "'.");
    }
    this.currentNamespace = currentNamespace;
  }


  /**
   *
   * @param namespace 被引用的命名空间
   */
  public void useCacheRef(String namespace) {
    if (namespace == null) {
      throw new BuilderException("cache-ref element requires a namespace attribute.");
    }
    try {
      // 1、尚未解析
      unresolvedCacheRef = true;
      // 2、根据namespace从configuration里获取缓存, (这里不就有个问题么，如果引用的命名空间缓存还未加载，这里就么得，所以必须先加载被引用的xml咯？)
      Cache cache = configuration.getCache(namespace);
      if (cache == null) {
        throw new IncompleteElementException("No cache for namespace '" + namespace + "' could be found.");
      }
      // 3、将引用过来的缓存赋值给当前缓存
      currentCache = cache;
      // 4、解析结束
      unresolvedCacheRef = false;
    } catch (IllegalArgumentException e) {
      throw new IncompleteElementException("No cache for namespace '" + namespace + "' could be found.", e);
    }
  }

  /**
   * 创建缓存
   * @param typeClass       缓存类型
   * @param evictionClass   淘汰策略
   * @param flushInterval   冲刷间隔
   * @param size            缓存大小
   * @param readWrite       读写权限
   * @param blocking        是否阻塞
   * @param props           额外属性
   */
  public void useNewCache(Class<? extends Cache> typeClass,
                          Class<? extends Cache> evictionClass,
                          Long flushInterval,
                          Integer size,
                          boolean readWrite,
                          boolean blocking,
                          Properties props) {
    // 1、判断typeClass和evictionClass 是否为null,为null就用默认值
    typeClass = valueOrDefault(typeClass, PerpetualCache.class);
    evictionClass = valueOrDefault(evictionClass, LruCache.class);
    // 2、调用CacheBuilder构建cache,id=currentNamespace
    Cache cache = new CacheBuilder(currentNamespace)
        .implementation(typeClass)
        .addDecorator(evictionClass)
        .clearInterval(flushInterval)
        .size(size)
        .readWrite(readWrite)
        .blocking(blocking)
        .properties(props)
        .build();
    // 3、加入configuration中的缓存集中营
    configuration.addCache(cache);
    // 4、设置为当前的缓存   （这么说Cache和Cache-ref是互斥的？？）
    currentCache = cache;
  }

  /**
   * 给某些节点的ID加上namespace前缀
   * e.q. 如rowResult-->com.pax.com.rowResult
   * @param base 一般是各种节点的ID
   * @param isReference 是否允许base中有圆点
   */
  public String applyCurrentNamespace(String base, boolean isReference) {
    if (base == null) {
      return null;
    }
    if (isReference) {
      if (base.contains(".")) {
        // 1、允许有圆点,那有的话直接返回
        return base;
      }
    } else {
      if (base.startsWith(currentNamespace + ".")) {
        // 2、不允许有圆点,但是以命名空间.开头也直接返回,否则直接报错
        return base;
      }
      if (base.contains(".")) {
        throw new BuilderException("Dots are not allowed in element names, please remove it from " + base);
      }
    }
    // 3、没有圆点就加上currentNamespace.返回
    return currentNamespace + "." + base;
  }


  /**
   * 构建ParameterMapping
   * @param parameterType 属性所在类 || 元素所在容器类型
   * @param property      属性名
   * @param javaType      属性java类型
   * @param jdbcType      属性jdbc类型
   * @param resultMap     属性的resultMap  ？？？
   * @param parameterMode 属性的parameterMode ？？？
   * @param typeHandler   属性的类型处理器
   * @param numericScale  属性的小数点保留几位
   * @return ParameterMapping
   */
  public ParameterMapping buildParameterMapping(
      Class<?> parameterType,
      String property,
      Class<?> javaType,
      JdbcType jdbcType,
      String resultMap,
      ParameterMode parameterMode,
      Class<? extends TypeHandler<?>> typeHandler,
      Integer numericScale) {
    // 1、给resultMap加上名称空间作为前缀
    resultMap = applyCurrentNamespace(resultMap, true);
    // 2、有时候不写明java类型,所以得给定一个java类型
    Class<?> javaTypeClass = resolveParameterJavaType(parameterType, property, javaType, jdbcType);
    // 3、获取类型处理器,如果没配置类型处理器,那这里会返回null,但是后面build时会构造一个默认的类型处理器
    TypeHandler<?> typeHandlerInstance = resolveTypeHandler(javaTypeClass, typeHandler);
    // 4、构建ParameterMapping
    ParameterMapping.Builder builder = new ParameterMapping.Builder(configuration, property, javaTypeClass);
    builder.jdbcType(jdbcType);
    builder.resultMapId(resultMap);
    builder.mode(parameterMode);
    builder.numericScale(numericScale);
    builder.typeHandler(typeHandlerInstance);
    return builder.build();
  }

  /**
   * 将parameterMap存到configuration
   * @param id   parameterMap 的 ID
   * @param parameterClass  parameterMap对应的clazz,这个clazz可能是个对象类,也可能是个容器类
   * @param parameterMappings  parameterMap 的所有 parameter
   */
  public void addParameterMap(String id, Class<?> parameterClass, List<ParameterMapping> parameterMappings) {
    id = applyCurrentNamespace(id, false);
    ParameterMap.Builder parameterMapBuilder = new ParameterMap.Builder(id, parameterClass, parameterMappings);
    ParameterMap parameterMap = parameterMapBuilder.build();
    configuration.addParameterMap(parameterMap);
  }


  //增加ResultMap
  public ResultMap addResultMap(
      String id,
      Class<?> type,
      String extend,
      Discriminator discriminator,
      List<ResultMapping> resultMappings,
      Boolean autoMapping) {
    id = applyCurrentNamespace(id, false);
    extend = applyCurrentNamespace(extend, true);

    //建造者模式
    ResultMap.Builder resultMapBuilder = new ResultMap.Builder(configuration, id, type, resultMappings, autoMapping);
    if (extend != null) {
      if (!configuration.hasResultMap(extend)) {
        throw new IncompleteElementException("Could not find a parent resultmap with id '" + extend + "'");
      }
      ResultMap resultMap = configuration.getResultMap(extend);
      List<ResultMapping> extendedResultMappings = new ArrayList<ResultMapping>(resultMap.getResultMappings());
      extendedResultMappings.removeAll(resultMappings);
      // Remove parent constructor if this resultMap declares a constructor.
      boolean declaresConstructor = false;
      for (ResultMapping resultMapping : resultMappings) {
        if (resultMapping.getFlags().contains(ResultFlag.CONSTRUCTOR)) {
          declaresConstructor = true;
          break;
        }
      }
      if (declaresConstructor) {
        Iterator<ResultMapping> extendedResultMappingsIter = extendedResultMappings.iterator();
        while (extendedResultMappingsIter.hasNext()) {
          if (extendedResultMappingsIter.next().getFlags().contains(ResultFlag.CONSTRUCTOR)) {
            extendedResultMappingsIter.remove();
          }
        }
      }
      resultMappings.addAll(extendedResultMappings);
    }
    resultMapBuilder.discriminator(discriminator);
    ResultMap resultMap = resultMapBuilder.build();
    configuration.addResultMap(resultMap);
    return resultMap;
  }

  public Discriminator buildDiscriminator(
      Class<?> resultType,
      String column,
      Class<?> javaType,
      JdbcType jdbcType,
      Class<? extends TypeHandler<?>> typeHandler,
      Map<String, String> discriminatorMap) {
    ResultMapping resultMapping = buildResultMapping(
        resultType,
        null,
        column,
        javaType,
        jdbcType,
        null,
        null,
        null,
        null,
        typeHandler,
        new ArrayList<ResultFlag>(),
        null,
        null,
        false);
    Map<String, String> namespaceDiscriminatorMap = new HashMap<String, String>();
    for (Map.Entry<String, String> e : discriminatorMap.entrySet()) {
      String resultMap = e.getValue();
      resultMap = applyCurrentNamespace(resultMap, true);
      namespaceDiscriminatorMap.put(e.getKey(), resultMap);
    }
    Discriminator.Builder discriminatorBuilder = new Discriminator.Builder(configuration, resultMapping, namespaceDiscriminatorMap);
    return discriminatorBuilder.build();
  }

  //增加映射语句
  public MappedStatement addMappedStatement(
      String id,
      SqlSource sqlSource,
      StatementType statementType,
      SqlCommandType sqlCommandType,
      Integer fetchSize,
      Integer timeout,
      String parameterMap,
      Class<?> parameterType,
      String resultMap,
      Class<?> resultType,
      ResultSetType resultSetType,
      boolean flushCache,
      boolean useCache,
      boolean resultOrdered,
      KeyGenerator keyGenerator,
      String keyProperty,
      String keyColumn,
      String databaseId,
      LanguageDriver lang,
      String resultSets) {

    if (unresolvedCacheRef) {
      throw new IncompleteElementException("Cache-ref not yet resolved");
    }

    //为id加上namespace前缀
    id = applyCurrentNamespace(id, false);
    //是否是select语句
    boolean isSelect = sqlCommandType == SqlCommandType.SELECT;

    //又是建造者模式
    MappedStatement.Builder statementBuilder = new MappedStatement.Builder(configuration, id, sqlSource, sqlCommandType);
    statementBuilder.resource(resource);
    statementBuilder.fetchSize(fetchSize);
    statementBuilder.statementType(statementType);
    statementBuilder.keyGenerator(keyGenerator);
    statementBuilder.keyProperty(keyProperty);
    statementBuilder.keyColumn(keyColumn);
    statementBuilder.databaseId(databaseId);
    statementBuilder.lang(lang);
    statementBuilder.resultOrdered(resultOrdered);
    statementBuilder.resulSets(resultSets);
    setStatementTimeout(timeout, statementBuilder);

    //1.参数映射
    setStatementParameterMap(parameterMap, parameterType, statementBuilder);
    //2.结果映射
    setStatementResultMap(resultMap, resultType, resultSetType, statementBuilder);
    setStatementCache(isSelect, flushCache, useCache, currentCache, statementBuilder);

    MappedStatement statement = statementBuilder.build();
    //建造好调用configuration.addMappedStatement
    configuration.addMappedStatement(statement);
    return statement;
  }

  private <T> T valueOrDefault(T value, T defaultValue) {
    return value == null ? defaultValue : value;
  }

  private void setStatementCache(
      boolean isSelect,
      boolean flushCache,
      boolean useCache,
      Cache cache,
      MappedStatement.Builder statementBuilder) {
    flushCache = valueOrDefault(flushCache, !isSelect);
    useCache = valueOrDefault(useCache, isSelect);
    statementBuilder.flushCacheRequired(flushCache);
    statementBuilder.useCache(useCache);
    statementBuilder.cache(cache);
  }

  private void setStatementParameterMap(
      String parameterMap,
      Class<?> parameterTypeClass,
      MappedStatement.Builder statementBuilder) {
    parameterMap = applyCurrentNamespace(parameterMap, true);

    if (parameterMap != null) {
      try {
        statementBuilder.parameterMap(configuration.getParameterMap(parameterMap));
      } catch (IllegalArgumentException e) {
        throw new IncompleteElementException("Could not find parameter map " + parameterMap, e);
      }
    } else if (parameterTypeClass != null) {
      List<ParameterMapping> parameterMappings = new ArrayList<ParameterMapping>();
      ParameterMap.Builder inlineParameterMapBuilder = new ParameterMap.Builder(
              statementBuilder.id() + "-Inline",
          parameterTypeClass,
          parameterMappings);
      statementBuilder.parameterMap(inlineParameterMapBuilder.build());
    }
  }

  //2.result map
  private void setStatementResultMap(
      String resultMap,
      Class<?> resultType,
      ResultSetType resultSetType,
      MappedStatement.Builder statementBuilder) {
    resultMap = applyCurrentNamespace(resultMap, true);

    List<ResultMap> resultMaps = new ArrayList<ResultMap>();
    if (resultMap != null) {
      //2.1 resultMap是高级功能
      String[] resultMapNames = resultMap.split(",");
      for (String resultMapName : resultMapNames) {
        try {
          resultMaps.add(configuration.getResultMap(resultMapName.trim()));
        } catch (IllegalArgumentException e) {
          throw new IncompleteElementException("Could not find result map " + resultMapName, e);
        }
      }
    } else if (resultType != null) {
      //2.2 resultType,一般用这个足矣了
      //<select id="selectUsers" resultType="User">
      //这种情况下,MyBatis 会在幕后自动创建一个 ResultMap,基于属性名来映射列到 JavaBean 的属性上。
      //如果列名没有精确匹配,你可以在列名上使用 select 字句的别名来匹配标签。
      //创建一个inline result map, 把resultType设上就OK了，
      //然后后面被DefaultResultSetHandler.createResultObject()使用
      //DefaultResultSetHandler.getRowValue()使用
      ResultMap.Builder inlineResultMapBuilder = new ResultMap.Builder(
          configuration,
          statementBuilder.id() + "-Inline",
          resultType,
          new ArrayList<ResultMapping>(),
          null);
      resultMaps.add(inlineResultMapBuilder.build());
    }
    statementBuilder.resultMaps(resultMaps);

    statementBuilder.resultSetType(resultSetType);
  }

  private void setStatementTimeout(Integer timeout, MappedStatement.Builder statementBuilder) {
    if (timeout == null) {
      timeout = configuration.getDefaultStatementTimeout();
    }
    statementBuilder.timeout(timeout);
  }

  //构建result map
  public ResultMapping buildResultMapping(
      Class<?> resultType,
      String property,
      String column,
      Class<?> javaType,
      JdbcType jdbcType,
      String nestedSelect,
      String nestedResultMap,
      String notNullColumn,
      String columnPrefix,
      Class<? extends TypeHandler<?>> typeHandler,
      List<ResultFlag> flags,
      String resultSet,
      String foreignColumn,
      boolean lazy) {
    Class<?> javaTypeClass = resolveResultJavaType(resultType, property, javaType);
    TypeHandler<?> typeHandlerInstance = resolveTypeHandler(javaTypeClass, typeHandler);
    //解析复合的列名,一般用不到，返回的是空
    List<ResultMapping> composites = parseCompositeColumnName(column);
    if (composites.size() > 0) {
      column = null;
    }
    //构建result map
    ResultMapping.Builder builder = new ResultMapping.Builder(configuration, property, column, javaTypeClass);
    builder.jdbcType(jdbcType);
    builder.nestedQueryId(applyCurrentNamespace(nestedSelect, true));
    builder.nestedResultMapId(applyCurrentNamespace(nestedResultMap, true));
    builder.resultSet(resultSet);
    builder.typeHandler(typeHandlerInstance);
    builder.flags(flags == null ? new ArrayList<ResultFlag>() : flags);
    builder.composites(composites);
    builder.notNullColumns(parseMultipleColumnNames(notNullColumn));
    builder.columnPrefix(columnPrefix);
    builder.foreignColumn(foreignColumn);
    builder.lazy(lazy);
    return builder.build();
  }

  private Set<String> parseMultipleColumnNames(String columnName) {
    Set<String> columns = new HashSet<String>();
    if (columnName != null) {
      if (columnName.indexOf(',') > -1) {
        StringTokenizer parser = new StringTokenizer(columnName, "{}, ", false);
        while (parser.hasMoreTokens()) {
          String column = parser.nextToken();
          columns.add(column);
        }
      } else {
        columns.add(columnName);
      }
    }
    return columns;
  }

  //解析复合列名，即列名由多个组成，可以先忽略
  private List<ResultMapping> parseCompositeColumnName(String columnName) {
    List<ResultMapping> composites = new ArrayList<ResultMapping>();
    if (columnName != null && (columnName.indexOf('=') > -1 || columnName.indexOf(',') > -1)) {
      StringTokenizer parser = new StringTokenizer(columnName, "{}=, ", false);
      while (parser.hasMoreTokens()) {
        String property = parser.nextToken();
        String column = parser.nextToken();
        ResultMapping.Builder complexBuilder = new ResultMapping.Builder(configuration, property, column, configuration.getTypeHandlerRegistry().getUnknownTypeHandler());
        composites.add(complexBuilder.build());
      }
    }
    return composites;
  }

  private Class<?> resolveResultJavaType(Class<?> resultType, String property, Class<?> javaType) {
    if (javaType == null && property != null) {
      try {
        MetaClass metaResultType = MetaClass.forClass(resultType);
        javaType = metaResultType.getSetterType(property);
      } catch (Exception e) {
        //ignore, following null check statement will deal with the situation
      }
    }
    if (javaType == null) {
      javaType = Object.class;
    }
    return javaType;
  }

  /**
   * 解析参数类型
   * @param resultType  属性所在类 || 元素所在容器
   * @param property 属性名
   * @param javaType 属性类型
   * @param jdbcType 属性对应的jdbc类型
   * @return
   */
  private Class<?> resolveParameterJavaType(Class<?> resultType, String property, Class<?> javaType, JdbcType jdbcType) {
    if (javaType == null) {
      if (JdbcType.CURSOR.equals(jdbcType)) {
        // 1、假如jdbcType是CURSOR,则javaType置为ResultSet类型
        javaType = java.sql.ResultSet.class;
      } else if (Map.class.isAssignableFrom(resultType)) {
        // 2、如果resultType是Map类型,这种定位不了具体类型，则javaType置为Object类型,
        javaType = Object.class;
      } else {
        // 3、假如jdbcType不是CURSOR、且resultType不是Map类型,则尝试利用MetaClass来根据属性名获取类型
        MetaClass metaResultType = MetaClass.forClass(resultType);
        javaType = metaResultType.getGetterType(property);
      }
    }
    if (javaType == null) {
      // 4、假如用户傻逼了,把属性名写错了,则javaType置为Object类型
      javaType = Object.class;
    }
    return javaType;
  }

  /** Backward compatibility signature */
  //向后兼容方法
  public ResultMapping buildResultMapping(
      Class<?> resultType,
      String property,
      String column,
      Class<?> javaType,
      JdbcType jdbcType,
      String nestedSelect,
      String nestedResultMap,
      String notNullColumn,
      String columnPrefix,
      Class<? extends TypeHandler<?>> typeHandler,
      List<ResultFlag> flags) {
      return buildResultMapping(
        resultType, property, column, javaType, jdbcType, nestedSelect,
        nestedResultMap, notNullColumn, columnPrefix, typeHandler, flags, null, null, configuration.isLazyLoadingEnabled());
  }

  //取得语言驱动
  public LanguageDriver getLanguageDriver(Class<?> langClass) {
    if (langClass != null) {
        //注册语言驱动
      configuration.getLanguageRegistry().register(langClass);
    } else {
        //如果为null，则取得默认驱动（mybatis3.2以前大家一直用的方法）
      langClass = configuration.getLanguageRegistry().getDefaultDriverClass();
    }
    //再去调configuration
    return configuration.getLanguageRegistry().getDriver(langClass);
  }

  /** Backward compatibility signature */
  //向后兼容方法
  public MappedStatement addMappedStatement(
    String id,
    SqlSource sqlSource,
    StatementType statementType,
    SqlCommandType sqlCommandType,
    Integer fetchSize,
    Integer timeout,
    String parameterMap,
    Class<?> parameterType,
    String resultMap,
    Class<?> resultType,
    ResultSetType resultSetType,
    boolean flushCache,
    boolean useCache,
    boolean resultOrdered,
    KeyGenerator keyGenerator,
    String keyProperty,
    String keyColumn,
    String databaseId,
    LanguageDriver lang) {
    return addMappedStatement(
      id, sqlSource, statementType, sqlCommandType, fetchSize, timeout,
      parameterMap, parameterType, resultMap, resultType, resultSetType,
      flushCache, useCache, resultOrdered, keyGenerator, keyProperty,
      keyColumn, databaseId, lang, null);
  }

}
