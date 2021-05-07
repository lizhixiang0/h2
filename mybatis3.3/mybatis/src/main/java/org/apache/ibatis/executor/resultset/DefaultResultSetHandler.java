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
package org.apache.ibatis.executor.resultset;

import java.lang.reflect.Constructor;
import java.sql.CallableStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.ErrorContext;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.ExecutorException;
import org.apache.ibatis.executor.loader.ResultLoader;
import org.apache.ibatis.executor.loader.ResultLoaderMap;
import org.apache.ibatis.executor.parameter.ParameterHandler;
import org.apache.ibatis.executor.result.DefaultResultContext;
import org.apache.ibatis.executor.result.DefaultResultHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.Discriminator;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.mapping.ParameterMode;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.mapping.ResultMapping;
import org.apache.ibatis.reflection.MetaClass;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.session.AutoMappingBehavior;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ResultContext;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.type.TypeHandler;
import org.apache.ibatis.type.TypeHandlerRegistry;

/**
 * 核心类,默认结果集处理器
 * @author Clinton Begin
 * @author Eduardo Macarron
 */
public class DefaultResultSetHandler implements ResultSetHandler {

  private static final Object NO_VALUE = new Object();

  private final Executor executor;
  private final Configuration configuration;
  private final MappedStatement mappedStatement;
  private final RowBounds rowBounds;
  private final ParameterHandler parameterHandler;
  private final ResultHandler resultHandler;
  private final BoundSql boundSql;
  private final TypeHandlerRegistry typeHandlerRegistry;
  private final ObjectFactory objectFactory;

  /**
   * 为当前resultMap维护了一个内嵌的缓存容器
   */
  private final Map<CacheKey, Object> nestedResultObjects = new HashMap<>();
  /**
   * 祖先对象
   */
  private final Map<CacheKey, Object> ancestorObjects = new HashMap<>();
  /**
   *祖先字段前缀
   */
  private final Map<String, String> ancestorColumnPrefix = new HashMap<>();

  // multiple resultsets
  private final Map<String, ResultMapping> nextResultMaps = new HashMap<>();
  private final Map<CacheKey, List<PendingRelation>> pendingRelations = new HashMap<>();

  public DefaultResultSetHandler(Executor executor, MappedStatement mappedStatement, ParameterHandler parameterHandler, ResultHandler resultHandler, BoundSql boundSql, RowBounds rowBounds) {
    this.executor = executor;
    this.configuration = mappedStatement.getConfiguration();
    this.mappedStatement = mappedStatement;
    this.rowBounds = rowBounds;
    this.parameterHandler = parameterHandler;
    this.boundSql = boundSql;
    this.typeHandlerRegistry = configuration.getTypeHandlerRegistry();
    this.objectFactory = configuration.getObjectFactory();
    this.resultHandler = resultHandler;
  }

  @Override
  public void handleOutputParameters(CallableStatement cs) throws SQLException {
    final Object parameterObject = parameterHandler.getParameterObject();
    final MetaObject metaParam = configuration.newMetaObject(parameterObject);
    final List<ParameterMapping> parameterMappings = boundSql.getParameterMappings();
    //循环处理每个参数
    for (int i = 0; i < parameterMappings.size(); i++) {
      final ParameterMapping parameterMapping = parameterMappings.get(i);
      //只处理OUT|INOUT
      if (parameterMapping.getMode() == ParameterMode.OUT || parameterMapping.getMode() == ParameterMode.INOUT) {
        if (ResultSet.class.equals(parameterMapping.getJavaType())) {
          //如果是ResultSet型(游标)
          //#{result, jdbcType=CURSOR, mode=OUT, javaType=ResultSet, resultMap=userResultMap}
          //先用CallableStatement.getObject取得这个游标，作为参数传进去
          handleRefCursorOutputParameter((ResultSet) cs.getObject(i + 1), parameterMapping, metaParam);
        } else {
          //否则是普通型，核心就是CallableStatement.getXXX取得值
          final TypeHandler<?> typeHandler = parameterMapping.getTypeHandler();
          metaParam.setValue(parameterMapping.getProperty(), typeHandler.getResult(cs, i + 1));
        }
      }
    }
  }

  //处理游标(OUT参数)
  private void handleRefCursorOutputParameter(ResultSet rs, ParameterMapping parameterMapping, MetaObject metaParam) throws SQLException {
    try {
      final String resultMapId = parameterMapping.getResultMapId();
      final ResultMap resultMap = configuration.getResultMap(resultMapId);
      final DefaultResultHandler resultHandler = new DefaultResultHandler(objectFactory);
      final ResultSetWrapper rsw = new ResultSetWrapper(rs, configuration);
      //里面就和一般ResultSet处理没两样了
      handleRowValues(rsw, resultMap, resultHandler, new RowBounds(), null);
      metaParam.setValue(parameterMapping.getProperty(), resultHandler.getResultList());
    } finally {
      // issue #228 (close resultsets)
      closeResultSet(rs);
    }
  }

  /**
   * 1、处理resultSet  (核心方法)
   * @param stmt
   * @return
   * @throws SQLException
   */
  @Override
  public List<Object> handleResultSets(Statement stmt) throws SQLException {
    ErrorContext.instance().activity("handling results").object(mappedStatement.getId());
    final List<Object> multipleResults = new ArrayList<>();
    int resultSetCount = 0;
    // 1、将ResultSet用包装器包装器来,里面会对ResultSet进行第一步的处理
    ResultSetWrapper rsw = getFirstResultSet(stmt);
    // 2、获得所有的resultMap,正常就只有一个,我没见过几个人配置多个的
    List<ResultMap> resultMaps = mappedStatement.getResultMaps();
    int resultMapCount = resultMaps.size();
    validateResultMapsCount(rsw, resultMapCount);

    // 3、遍历resultMaps
    while (rsw != null && resultMapCount > resultSetCount) {
      ResultMap resultMap = resultMaps.get(resultSetCount);
      // a、处理ResultSet,将查询到的数据,映射到当前ResultMap配置的对象中去
      handleResultSet(rsw, resultMap, multipleResults, null);
      // b、获取下一个结果集
      rsw = getNextResultSet(stmt);
      //
      cleanUpAfterHandlingResultSet();
      resultSetCount++;
    }

    String[] resultSets = mappedStatement.getResulSets();
    if (resultSets != null) {
      while (rsw != null && resultSetCount < resultSets.length) {
        ResultMapping parentMapping = nextResultMaps.get(resultSets[resultSetCount]);
        if (parentMapping != null) {
          String nestedResultMapId = parentMapping.getNestedResultMapId();
          ResultMap resultMap = configuration.getResultMap(nestedResultMapId);
          handleResultSet(rsw, resultMap, null, parentMapping);
        }
        rsw = getNextResultSet(stmt);
        cleanUpAfterHandlingResultSet();
        resultSetCount++;
      }
    }

    return collapseSingleResultList(multipleResults);
  }

  /**
   * 2、从Statement中获得ResultSet后用ResultSetWrapper包装器起来返回
   * @param stmt
   * @return
   * @throws SQLException
   */
  private ResultSetWrapper getFirstResultSet(Statement stmt) throws SQLException {
    // 1、获取结果集
    ResultSet rs = stmt.getResultSet();
    while (rs == null) {
      // a、如果驱动程序没有将结果集作为第一个结果返回，则继续获取第一个结果集  （HSQL数据库2.1特殊情况处理）
      if (stmt.getMoreResults()) {
        rs = stmt.getResultSet();
      } else {
        // b、么得结果集就break
        if (stmt.getUpdateCount() == -1) {
          break;
        }
      }
    }
    // 2、将结果集用ResultSetWrapper包装器起来返回
    return rs != null ? new ResultSetWrapper(rs, configuration) : null;
  }

  /**
   * 3、验证是否配置了ResultMap
   * 如果该sql语句配置了ResultMap最好,没配置就看有没有配置resultType,mybatis会根据这个创建一个ResultMap
   * @param rsw
   * @param resultMapCount
   */
  private void validateResultMapsCount(ResultSetWrapper rsw, int resultMapCount) {
    if (rsw != null && resultMapCount < 1) {
      throw new ExecutorException("A query was run and no Result Maps were found for the Mapped Statement '" + mappedStatement.getId() + "'.  It's likely that neither a Result Type nor a Result Map was specified.");
    }
  }

  /**
   * 4、处理结果集
   * @param rsw  resultSet包装类
   * @param resultMap  结果集映射表
   * @param multipleResults  存储所有结果的容器
   * @param parentMapping ？
   * @throws SQLException
   */
  private void handleResultSet(ResultSetWrapper rsw, ResultMap resultMap, List<Object> multipleResults, ResultMapping parentMapping) throws SQLException {
    try {
      // ??
      if (parentMapping != null) {
        handleRowValues(rsw, resultMap, null, RowBounds.DEFAULT, parentMapping);
      } else {
        if (resultHandler == null) {
          // 1、如果没有resultHandler (事实上传的就是null),创建默认处理器DefaultResultHandler
          DefaultResultHandler defaultResultHandler = new DefaultResultHandler(objectFactory);
          // 2、调用自己的handleRowValues
          handleRowValues(rsw, resultMap, defaultResultHandler, rowBounds, null);
          // 3、将得到的结果从结果处理器里拿出来存到multipleResults里
          multipleResults.add(defaultResultHandler.getResultList());
        } else {
          // 如果有resultHandler,走这里,么得区别
          handleRowValues(rsw, resultMap, resultHandler, rowBounds, null);
        }
      }
    } finally {
      //最后别忘了关闭结果集
      closeResultSet(rsw.getResultSet());
    }
  }

  /**
   * 5、处理数据
   * @param rsw   结果集
   * @param resultMap   结果集映射表
   * @param resultHandler   结果处理器
   * @param rowBounds   list查询时控制最多返回数
   * @param parentMapping  ？？
   * @throws SQLException
   */
  private void handleRowValues(ResultSetWrapper rsw, ResultMap resultMap, ResultHandler resultHandler, RowBounds rowBounds, ResultMapping parentMapping) throws SQLException {
    if (resultMap.hasNestedResultMaps()) {
      // 1、当前ResultMap存在内嵌的ResultMap,走这里  （需要检查有没有自定义的RowBound和resultHandler）
      ensureNoRowBounds();
      checkResultHandler();
      handleRowValuesForNestedResultMap(rsw, resultMap, resultHandler, rowBounds, parentMapping);
    } else {
      // 2、当前ResultMap不存在内嵌的ResultMap,走这里
      handleRowValuesForSimpleResultMap(rsw, resultMap, resultHandler, rowBounds, parentMapping);
    }
  }

  /**
   * 处理带有内嵌resultMap的结果映射
   * @param rsw
   * @param resultMap
   * @param resultHandler
   * @param rowBounds
   * @param parentMapping
   * @throws SQLException
   */
  private void handleRowValuesForNestedResultMap(ResultSetWrapper rsw, ResultMap resultMap, ResultHandler resultHandler, RowBounds rowBounds, ResultMapping parentMapping) throws SQLException {
    final DefaultResultContext resultContext = new DefaultResultContext();
    // 1、跳过偏移量
    skipRows(rsw.getResultSet(), rowBounds);
    Object rowValue = null;
    // 2、在允许读取的最大行数内进行while循环,同时进行数据的处理
    while (shouldProcessMoreRows(resultContext, rowBounds) && rsw.getResultSet().next()) {
      // a、获取鉴别器中适配到的resultMap
      final ResultMap discriminatedResultMap = resolveDiscriminatedResultMap(rsw.getResultSet(), resultMap, null);
      // b、为这个嵌套的resultMap建立缓存key
      final CacheKey rowKey = createRowKey(discriminatedResultMap, rsw, null);
      // c、先尝试从缓存中取这个内嵌的那部分映射对象
      Object partialObject = nestedResultObjects.get(rowKey);

      if (mappedStatement.isResultOrdered()) {
        // 如果该sql映射语句要求结果有序,且没能从缓存中取出内嵌的那部分映射对象，且rowValue不为null
        if (partialObject == null && rowValue != null) {
          // I、清空内嵌缓存容器
          nestedResultObjects.clear();
          // II、存储当前行转化的对象
          storeObject(resultHandler, resultContext, rowValue, parentMapping, rsw.getResultSet());
        }
        // 获取当前行的映射结果
        rowValue = getRowValue(rsw, discriminatedResultMap, rowKey, rowKey, null, partialObject);
      } else {
        // 如果该sql映射语句没要求结果有序
        rowValue = getRowValue(rsw, discriminatedResultMap, rowKey, rowKey, null, partialObject);

        if (partialObject == null) {
          storeObject(resultHandler, resultContext, rowValue, parentMapping, rsw.getResultSet());
        }
      }
    }
    if (rowValue != null && mappedStatement.isResultOrdered() && shouldProcessMoreRows(resultContext, rowBounds)) {
      storeObject(resultHandler, resultContext, rowValue, parentMapping, rsw.getResultSet());
    }
  }

  /**
   * 为内嵌的resultMap创建缓存key
   * @param resultMap  内嵌的resultMap
   * @param rsw    ResultSet
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private CacheKey createRowKey(ResultMap resultMap, ResultSetWrapper rsw, String columnPrefix) throws SQLException {
    final CacheKey cacheKey = new CacheKey();
    // 1、第一个变量
    cacheKey.update(resultMap.getId());
    // 2、获取结果映射集合
    List<ResultMapping> resultMappings = getResultMappingsForRowKey(resultMap);

    if (resultMappings.size() == 0) {
      if (Map.class.isAssignableFrom(resultMap.getType())) {
        // a、如果没有ResultMapping,且resultMap.getType()是Map类型,走这里
        createRowKeyForMap(rsw, cacheKey);
      } else {
        // b、如果没有ResultMapping,且resultMap.getType()不是Map类型,走这里
        createRowKeyForUnmappedProperties(resultMap, rsw, cacheKey, columnPrefix);
      }
    } else {
      // c、如果有ResultMapping,走这
      createRowKeyForMappedProperties(resultMap, rsw, cacheKey, resultMappings, columnPrefix);
    }
    // 3、返回缓存key
    return cacheKey;

  }

  /**
   * 获取结果映射集合
   * @param resultMap
   * @return
   */
  private List<ResultMapping> getResultMappingsForRowKey(ResultMap resultMap) {
    List<ResultMapping> resultMappings = resultMap.getIdResultMappings();
    if (resultMappings.size() == 0) {
      resultMappings = resultMap.getPropertyResultMappings();
    }
    return resultMappings;
  }

  /**
   * 如果没有ResultMapping,且resultMap.getType()是Map类型,走这里
   * @param rsw
   * @param cacheKey
   * @throws SQLException
   */
  private void createRowKeyForMap(ResultSetWrapper rsw, CacheKey cacheKey) throws SQLException {
    List<String> columnNames = rsw.getColumnNames();
    for (String columnName : columnNames) {
      final String value = rsw.getResultSet().getString(columnName);
      if (value != null) {
        // 用ResultSet中的所有字段名和值来构成cacheKey
        cacheKey.update(columnName);
        cacheKey.update(value);
      }
    }
  }

  /**
   * 如果没有ResultMapping,且resultMap.getType()不是Map类型,走这里
   * @param resultMap
   * @param rsw
   * @param cacheKey
   * @param columnPrefix
   * @throws SQLException
   */
  private void createRowKeyForUnmappedProperties(ResultMap resultMap, ResultSetWrapper rsw, CacheKey cacheKey, String columnPrefix) throws SQLException {
    final MetaClass metaType = MetaClass.forClass(resultMap.getType());
    // 1、获取所有未映射的字段 (其实在这种情况下就是所有字段了)
    List<String> unmappedColumnNames = rsw.getUnmappedColumnNames(resultMap, columnPrefix);
    for (String column : unmappedColumnNames) {
      String property = column;
      // a、给属性增加前缀
      if (columnPrefix != null && !columnPrefix.isEmpty()) {
        if (column.toUpperCase(Locale.ENGLISH).startsWith(columnPrefix)) {
          property = column.substring(columnPrefix.length());
        } else {
          continue;
        }
      }
      if (metaType.findProperty(property, configuration.isMapUnderscoreToCamelCase()) != null) {
        String value = rsw.getResultSet().getString(column);
        if (value != null) {
          // b、用字段名和值来构成cacheKey,必须是能在metaType中找到的字段
          cacheKey.update(column);
          cacheKey.update(value);
        }
      }
    }
  }

  /**
   * 如果有ResultMapping,走这
   * @param resultMap
   * @param rsw
   * @param cacheKey
   * @param resultMappings
   * @param columnPrefix
   * @throws SQLException
   */
  private void createRowKeyForMappedProperties(ResultMap resultMap, ResultSetWrapper rsw, CacheKey cacheKey, List<ResultMapping> resultMappings, String columnPrefix) throws SQLException {
    // 直接遍历resultMappings
    for (ResultMapping resultMapping : resultMappings) {
      if (resultMapping.getNestedResultMapId() != null && resultMapping.getResultSet() == null) {
        final ResultMap nestedResultMap = configuration.getResultMap(resultMapping.getNestedResultMapId());
        // resultMapping里面还有嵌套的ResultMapId,递归...
        createRowKeyForMappedProperties(nestedResultMap, rsw, cacheKey, nestedResultMap.getConstructorResultMappings(), prependPrefix(resultMapping.getColumnPrefix(), columnPrefix));
      } else if (resultMapping.getNestedQueryId() == null) {
        final String column = prependPrefix(resultMapping.getColumn(), columnPrefix);
        final TypeHandler<?> th = resultMapping.getTypeHandler();
        List<String> mappedColumnNames = rsw.getMappedColumnNames(resultMap, columnPrefix);
        if (column != null && mappedColumnNames.contains(column.toUpperCase(Locale.ENGLISH))) {
          final Object value = th.getResult(rsw.getResultSet(), column);
          if (value != null) {
            // 用字段名和值来构成cacheKey,必须是能在mappedColumnNames中找到的字段
            cacheKey.update(column);
            cacheKey.update(value);
          }
        }
      }
    }
  }

  /**
   *
   * @param rsw
   * @param resultMap
   * @param combinedKey
   * @param absoluteKey
   * @param columnPrefix
   * @param partialObject
   * @return
   * @throws SQLException
   */
  private Object getRowValue(ResultSetWrapper rsw, ResultMap resultMap, CacheKey combinedKey, CacheKey absoluteKey, String columnPrefix, Object partialObject) throws SQLException {
    // 1、获取resultMapId
    final String resultMapId = resultMap.getId();
    // ?
    Object resultObject = partialObject;
    // ?
    if (resultObject != null) {
      final MetaObject metaObject = configuration.newMetaObject(resultObject);
      putAncestor(absoluteKey, resultObject, resultMapId, columnPrefix);
      applyNestedResultMappings(rsw, resultMap, metaObject, columnPrefix, combinedKey, false);
      ancestorObjects.remove(absoluteKey);
    } else {
      // 创建延迟加载容器
      final ResultLoaderMap lazyLoader = new ResultLoaderMap();
      // 根据resultMap构建结果对象
      resultObject = createResultObject(rsw, resultMap, lazyLoader, columnPrefix);
      // 如果resultObject不为null,且不是基本类型
      if (resultObject != null && !typeHandlerRegistry.hasTypeHandler(resultMap.getType())) {
        // a、创建元对象
        final MetaObject metaObject = configuration.newMetaObject(resultObject);
        // b、判断有没有读出来数据过 （如果resultMap配了Constructor节点,那肯定是读出来数据了）
        boolean foundValues = !resultMap.getConstructorResultMappings().isEmpty();
        if (shouldApplyAutomaticMappings(resultMap, true)) {
          // c、如果该resultMap配置了自动映射,则执行自动映射
          foundValues = applyAutomaticMappings(rsw, resultMap, metaObject, columnPrefix) || foundValues;
        }
        // d、不管配没配自动映射，这里给对象赋值
        foundValues = applyPropertyMappings(rsw, resultMap, metaObject, lazyLoader, columnPrefix) || foundValues;
        // e、
        putAncestor(absoluteKey, resultObject, resultMapId, columnPrefix);
        foundValues = applyNestedResultMappings(rsw, resultMap, metaObject, columnPrefix, combinedKey, true) || foundValues;
        ancestorObjects.remove(absoluteKey);
        foundValues = lazyLoader.size() > 0 || foundValues;
        resultObject = foundValues ? resultObject : null;
      }
      if (combinedKey != CacheKey.NULL_CACHE_KEY) {
        nestedResultObjects.put(combinedKey, resultObject);
      }
    }
    return resultObject;
  }

  /**
   *
   * @param rowKey
   * @param resultObject
   * @param resultMapId
   * @param columnPrefix
   */
  private void putAncestor(CacheKey rowKey, Object resultObject, String resultMapId, String columnPrefix) {
    if (!ancestorColumnPrefix.containsKey(resultMapId)) {
      ancestorColumnPrefix.put(resultMapId, columnPrefix);
    }
    ancestorObjects.put(rowKey, resultObject);
  }

  /**
   * 6、处理数据
   * @param rsw  结果集
   * @param resultMap  结果集映射表
   * @param resultHandler   结果集处理器
   * @param rowBounds  list查询时控制最多返回数
   * @param parentMapping
   * @throws SQLException
   */
  private void handleRowValuesForSimpleResultMap(ResultSetWrapper rsw, ResultMap resultMap, ResultHandler resultHandler, RowBounds rowBounds, ResultMapping parentMapping) throws SQLException {
    DefaultResultContext resultContext = new DefaultResultContext();
    // 1、跳过偏移量
    skipRows(rsw.getResultSet(), rowBounds);
    // 2、在允许读取的最大行数内进行while循环,同时进行数据的处理
    while (shouldProcessMoreRows(resultContext, rowBounds) && rsw.getResultSet().next()) {
      // a、获取鉴别器中适配的resultMap
      ResultMap discriminatedResultMap = resolveDiscriminatedResultMap(rsw.getResultSet(), resultMap, null);
      // b、处理一行数据得到的结果对象
      Object rowValue = getRowValue(rsw, discriminatedResultMap);
      // c、存储对象
      storeObject(resultHandler, resultContext, rowValue, parentMapping, rsw.getResultSet());
    }
  }

  /**
   * 7、跳过偏移量
   * @param rs
   * @param rowBounds
   * @throws SQLException
   */
  private void skipRows(ResultSet rs, RowBounds rowBounds) throws SQLException {
    // 1、如果ResultSet的游标可以上下滚动,jdk1的时候只支持向下next()滚动,但到了jdk2的时候就支持向上滚动previous()和直接跑到第一行first()和最后一行last()
    if (rs.getType() != ResultSet.TYPE_FORWARD_ONLY) {
      if (rowBounds.getOffset() != RowBounds.NO_ROW_OFFSET) {
        // 同时也支持直接将光标移到给定的行号absolute()
        rs.absolute(rowBounds.getOffset());
      }
    } else {
      // 2、如果ResultSet的游标只能向下滚动,那就直接跳过设置的数量
      for (int i = 0; i < rowBounds.getOffset(); i++) {
        rs.next();
      }
    }
  }

  /**
   * 8、控制数据量,必须小于用户设置的最大限制
   *
   * @param context
   * @param rowBounds
   * @return
   */
  private boolean shouldProcessMoreRows(ResultContext context, RowBounds rowBounds) {
    return !context.isStopped() && context.getResultCount() < rowBounds.getLimit();
  }

  /**
   * 9、处理resultMap中的鉴别器（返回鉴别器中适配到的resultMap）
   * @param rs   结果集
   * @param resultMap   结果映射表
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  public ResultMap resolveDiscriminatedResultMap(ResultSet rs, ResultMap resultMap, String columnPrefix) throws SQLException {
    // 1、创建无序不重复Hash集合
    Set<String> pastDiscriminators = new HashSet<>();
    // 2、获取当前resultMap的鉴别器
    Discriminator discriminator = resultMap.getDiscriminator();

    while (discriminator != null) {
      // a、获得鉴别器中匹配到的resultMap
      final Object value = getDiscriminatorValue(rs, discriminator, columnPrefix);
      final String discriminatedMapId = discriminator.getMapIdFor(String.valueOf(value));
      // b、查看configuration中是否存在此resultMap,存在则处理，不存在则跳过循环
      if (configuration.hasResultMap(discriminatedMapId)) {
        // c、取出鉴别器内部的resultMap赋值给resultMap  (这里呢,我一开始还没理解过来,形参和实参)
        resultMap = configuration.getResultMap(discriminatedMapId);
        // d、将鉴别器赋值给新创建的lastDiscriminator
        Discriminator lastDiscriminator = discriminator;
        // c、尝试获取鉴别器中匹配到的resultMap内部鉴别器（拿不到则为null）
        discriminator = resultMap.getDiscriminator();
        // d、当获得的鉴别器和外面包围的鉴别器是同一个则跳出循环,或者当pastDiscriminators出现了重复的resultMap也跳出循环
        if (discriminator == lastDiscriminator || !pastDiscriminators.add(discriminatedMapId)) {
          break;
        }
      } else {
        break;
      }
    }
    // 3、没配置鉴别器,不做任何处理，配置了鉴别器就返回适配到的resultMap
    return resultMap;
  }

  /**
   * 10、从ResultSet取出当前鉴别器的value值
   * @param rs   结果集
   * @param discriminator   鉴别器
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object getDiscriminatorValue(ResultSet rs, Discriminator discriminator, String columnPrefix) throws SQLException {
    final ResultMapping resultMapping = discriminator.getResultMapping();
    final TypeHandler<?> typeHandler = resultMapping.getTypeHandler();
    return typeHandler.getResult(rs, prependPrefix(resultMapping.getColumn(), columnPrefix));
  }

  /**
   * 11、给字段名加上前缀
   * @param columnName
   * @param prefix
   * @return
   */
  private String prependPrefix(String columnName, String prefix) {
    if (columnName == null || columnName.length() == 0 || prefix == null || prefix.length() == 0) {
      return columnName;
    }
    return prefix + columnName;
  }

  /**
   * 12、核心，处理一行数据
   * @param rsw ResultSet
   * @param resultMap resultMap
   * @return
   * @throws SQLException
   */
  private Object getRowValue(ResultSetWrapper rsw, ResultMap resultMap) throws SQLException {
    // 1、实例化ResultLoaderMap(延迟加载器)
    final ResultLoaderMap lazyLoader = new ResultLoaderMap();
    // 2、调用自己的createResultObject,内部就是new一个对象(如果是简单类型，new完也把值赋进去)
    Object resultObject = createResultObject(rsw, resultMap, lazyLoader, null);
    // 3、为resultObject对象赋值 （一般只有简单类型有typeHandler,会被过滤掉）
    if (resultObject != null && !typeHandlerRegistry.hasTypeHandler(resultMap.getType())) {
      final MetaObject metaObject = configuration.newMetaObject(resultObject);
      // 4、如果配置了<constructor>则foundValues为true
      boolean foundValues = !resultMap.getConstructorResultMappings().isEmpty();
      // 5、如果配置了自动映射,则执行自动映射
      if (shouldApplyAutomaticMappings(resultMap, false)) {
        foundValues = applyAutomaticMappings(rsw, resultMap, metaObject, null) || foundValues;
      }
      // 接着处理,给结果对象设置属性
      foundValues = applyPropertyMappings(rsw, resultMap, metaObject, lazyLoader, null) || foundValues;
      foundValues = lazyLoader.size() > 0 || foundValues;
      resultObject = foundValues ? resultObject : null;
      return resultObject;
    }
    return resultObject;
  }

  /**
   * 13、根据resultMap创建结果对象1
   * @param rsw
   * @param resultMap
   * @param lazyLoader
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object createResultObject(ResultSetWrapper rsw, ResultMap resultMap, ResultLoaderMap lazyLoader, String columnPrefix) throws SQLException {
    final List<Class<?>> constructorArgTypes = new ArrayList<>();
    final List<Object> constructorArgs = new ArrayList<>();
    // 1、创建resultMap里配置的resultType对象
    final Object resultObject = createResultObject(rsw, resultMap, constructorArgTypes, constructorArgs, columnPrefix);

    // 2、如果对象中存在延迟加载属性,则创建对应的代理对象（如果是简单类型,在createResultObject时就已经赋值了,所以这里过滤掉）
    if (resultObject != null && !typeHandlerRegistry.hasTypeHandler(resultMap.getType())) {
      final List<ResultMapping> propertyMappings = resultMap.getPropertyResultMappings();
      // 3、循环遍历普通属性映射容器（与此对比的是构造器里的属性,在createResultObject时就已经赋值）
      for (ResultMapping propertyMapping : propertyMappings) {
        if (propertyMapping.getNestedQueryId() != null && propertyMapping.isLazy()) {
          // 假如其中某个ResultMapping映射配置了内嵌的查询语句和懒加载,则创建代理对象并返回
          return configuration.getProxyFactory().createProxy(resultObject, lazyLoader, configuration, objectFactory, constructorArgTypes, constructorArgs);
        }
      }
    }
    return resultObject;
  }

  /**
   * 14、创建结果对象2
   * @param rsw 结果集
   * @param resultMap   结果映射表
   * @param constructorArgTypes   构造函数的参数类型容器
   * @param constructorArgs   构造函数的参数容器
   * @param columnPrefix  前缀
   * @return
   * @throws SQLException
   */
  private Object createResultObject(ResultSetWrapper rsw, ResultMap resultMap, List<Class<?>> constructorArgTypes, List<Object> constructorArgs, String columnPrefix)
          throws SQLException {
    // 1、得到resultType
    final Class<?> resultType = resultMap.getType();
    final MetaClass metaType = MetaClass.forClass(resultType);
    // 2、得到<constructor>节点下的映射表
    final List<ResultMapping> constructorMappings = resultMap.getConstructorResultMappings();

    if (typeHandlerRegistry.hasTypeHandler(resultType)) {
      // a、如果resultType有专门的类型处理器(一般不会给复杂类型配置处理器,只有简单类型没有mybatis自己配了，所以这种情况意味着resultSet只有一列)
      return createPrimitiveResultObject(rsw, resultMap, columnPrefix);
    } else if (!constructorMappings.isEmpty()) {
      // b、如果没有专门的resultType类型处理器，则说明是复杂类型,此时若配置了<constructor>，则走这里
      return createParameterizedResultObject(rsw, resultType, constructorMappings, constructorArgTypes, constructorArgs, columnPrefix);
    } else if (resultType.isInterface() || metaType.hasDefaultConstructor()) {
      // c、没有配置resultType类型处理器,也没配置<constructor>,但该对象存在无参构造方法,则直接通过对象工厂创建对象并返回
      return objectFactory.create(resultType);
    } else if (shouldApplyAutomaticMappings(resultMap, false)) {
      // d、该对象没有无参构造(应该是有参构造),也没配置<constructor>,但是该resultMap配置了自动映射，则走这里
      return createByConstructorSignature(rsw, resultType, constructorArgTypes, constructorArgs, columnPrefix);
    }
    throw new ExecutorException("Do not know how to create an instance of " + resultType);
  }

  /**
   * 15.1、简单类型走这里 （既然走了简单类型,说明是单列的结果集）
   * @param rsw
   * @param resultMap
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object createPrimitiveResultObject(ResultSetWrapper rsw, ResultMap resultMap, String columnPrefix) throws SQLException {
    final Class<?> resultType = resultMap.getType();
    final String columnName;
    if (!resultMap.getResultMappings().isEmpty()) {
      final List<ResultMapping> resultMappingList = resultMap.getResultMappings();
      // 配置了ResultMapping则从该对象中取列名,正常只有一个,所以get(0)
      final ResultMapping mapping = resultMappingList.get(0);
      columnName = prependPrefix(mapping.getColumn(), columnPrefix);
    } else {
      // 没有配置ResultMapping则从ResultSet里拿，因为只有一列，所以get(0)
      columnName = rsw.getColumnNames().get(0);
    }
    // 1、取出类型处理器
    final TypeHandler<?> typeHandler = rsw.getTypeHandler(resultType, columnName);
    // 2、根据列名取出数据
    return typeHandler.getResult(rsw.getResultSet(), columnName);
  }

  /**
   *
   * 15.2、没有专门的resultType类型处理器,但配置了<constructor>,则处理下构造方法参数映射表，将数据处理好放到对应的容器里去,并且根据构造方法、构造参数、具体类型创建对象并返回
   * @param rsw
   * @param resultType
   * @param constructorMappings   构造参数映射表
   * @param constructorArgTypes   用来存储构造方法的参数类型容器
   * @param constructorArgs       用来存储构造方法的参数容器
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object createParameterizedResultObject(ResultSetWrapper rsw, Class<?> resultType, List<ResultMapping> constructorMappings, List<Class<?>> constructorArgTypes, List<Object> constructorArgs, String columnPrefix) throws SQLException {
    boolean foundValues = false;
    // 遍历构造参数映射表
    for (ResultMapping constructorMapping : constructorMappings) {
      // 1、获取参数类型
      final Class<?> parameterType = constructorMapping.getJavaType();
      // 2、获取配置的字段名
      final String column = constructorMapping.getColumn();
      final Object value;
      // 3、处理对应结果
      if (constructorMapping.getNestedQueryId() != null) {
        // a、假如该ResultMapping配置了内置查询语句,则走这里,从ResultSet里拿到参数值,再去执行内嵌sql,查出对应的value
        value = getNestedQueryConstructorValue(rsw.getResultSet(), constructorMapping, columnPrefix);
      } else if (constructorMapping.getNestedResultMapId() != null) {
        // b、如果没有配置内置查询语句,但是配置了内置的ResultMapId,走这里
        final ResultMap resultMap = configuration.getResultMap(constructorMapping.getNestedResultMapId());
        value = getRowValue(rsw, resultMap);
      } else {
        // c、既没配置内置语句,也没配置内置ResultMap,则走这里 （这才是最正常的路线）
        final TypeHandler<?> typeHandler = constructorMapping.getTypeHandler();
        value = typeHandler.getResult(rsw.getResultSet(), prependPrefix(column, columnPrefix));
      }
      constructorArgTypes.add(parameterType);
      constructorArgs.add(value);
      foundValues = value != null || foundValues;
    }
    return foundValues ? objectFactory.create(resultType, constructorArgTypes, constructorArgs) : null;
  }

  /**
   * 15.3、该对象没有无参构造(应该是有参构造),也没配置<constructor>,但是该resultMap配置了自动映射，则走这里
   *       这里其实就是利用有参构造创建结果对象,我们可以看到里面走了两层for循环，比较麻烦
   * @param rsw
   * @param resultType
   * @param constructorArgTypes
   * @param constructorArgs
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object createByConstructorSignature(ResultSetWrapper rsw, Class<?> resultType, List<Class<?>> constructorArgTypes, List<Object> constructorArgs, String columnPrefix) throws SQLException {
    // 遍历有参构造
    for (Constructor<?> constructor : resultType.getDeclaredConstructors()) {
      // 比较参数名是否匹配 (这里用的list的equals方法)
      if (typeNames(constructor.getParameterTypes()).equals(rsw.getClassNames())) {
        boolean foundValues = false;
        for (int i = 0; i < constructor.getParameterTypes().length; i++) {
          Class<?> parameterType = constructor.getParameterTypes()[i];
          String columnName = rsw.getColumnNames().get(i);
          TypeHandler<?> typeHandler = rsw.getTypeHandler(parameterType, columnName);
          Object value = typeHandler.getResult(rsw.getResultSet(), prependPrefix(columnName, columnPrefix));
          constructorArgTypes.add(parameterType);
          constructorArgs.add(value);
          foundValues = value != null || foundValues;
        }
        // 利用对象工厂创建对象
        return foundValues ? objectFactory.create(resultType, constructorArgTypes, constructorArgs) : null;
      }
    }
    throw new ExecutorException("No constructor found in " + resultType.getName() + " matching " + rsw.getClassNames());
  }

  /**
   * 15.3.1、取出有参构造方法的所有参数名放到list容器
   * @param parameterTypes
   * @return
   */
  private List<String> typeNames(Class<?>[] parameterTypes) {
    List<String> names = new ArrayList<>();
    for (Class<?> type : parameterTypes) {
      names.add(type.getName());
    }
    return names;
  }

  /**
   * 16.1、<constructor>节点中的ResultMapping配置了内置语句,则走这里
   * @param rs
   * @param constructorMapping
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object getNestedQueryConstructorValue(ResultSet rs, ResultMapping constructorMapping, String columnPrefix) throws SQLException {
    final String nestedQueryId = constructorMapping.getNestedQueryId();
    final MappedStatement nestedQuery = configuration.getMappedStatement(nestedQueryId);
    // 1、获取内嵌sql语句需要的参数类型
    final Class<?> nestedQueryParameterType = nestedQuery.getParameterMap().getType();
    // 2、为嵌套查询准备参数
    final Object nestedQueryParameterObject = prepareParameterForNestedQuery(rs, constructorMapping, nestedQueryParameterType, columnPrefix);
    Object value = null;
    if (nestedQueryParameterObject != null) {
      final BoundSql nestedBoundSql = nestedQuery.getBoundSql(nestedQueryParameterObject);
      final CacheKey key = executor.createCacheKey(nestedQuery, nestedQueryParameterObject, RowBounds.DEFAULT, nestedBoundSql);
      final Class<?> targetType = constructorMapping.getJavaType();
      // 3、走ResultLoader把结果查出来
      final ResultLoader resultLoader = new ResultLoader(configuration, executor, nestedQuery, nestedQueryParameterObject, targetType, key, nestedBoundSql);
      value = resultLoader.loadResult();
    }
    // 4、返回内嵌查询语句查出来的结果
    return value;
  }

  /**
   * 16.1.1、为嵌套查询准备参数
   * @param rs
   * @param resultMapping
   * @param parameterType
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object prepareParameterForNestedQuery(ResultSet rs, ResultMapping resultMapping, Class<?> parameterType, String columnPrefix) throws SQLException {
    if (resultMapping.isCompositeResult()) {
      return prepareCompositeKeyParameter(rs, resultMapping, parameterType, columnPrefix);
    } else {
      return prepareSimpleKeyParameter(rs, resultMapping, parameterType, columnPrefix);
    }
  }

  /**
   * 16.1.1.1、为嵌套查询准备参数-复合键
   * 可以使用 column="{prop1=col1,prop2=col2}" 这样的语法来传递多个参数给内嵌Select查询语句
   * @param rs
   * @param resultMapping
   * @param parameterType
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object prepareCompositeKeyParameter(ResultSet rs, ResultMapping resultMapping, Class<?> parameterType, String columnPrefix) throws SQLException {
    // 1、实例化参数对象(传递多个参数,一般是HashMap比较ok)
    final Object parameterObject = instantiateParameterObject(parameterType);
    final MetaObject metaObject = configuration.newMetaObject(parameterObject);
    boolean foundValues = false;
    // 2、遍历,将ResultSet中的数据放到参数对象里返回
    for (ResultMapping innerResultMapping : resultMapping.getComposites()) {
      final Class<?> propType = metaObject.getSetterType(innerResultMapping.getProperty());
      final TypeHandler<?> typeHandler = typeHandlerRegistry.getTypeHandler(propType);
      final Object propValue = typeHandler.getResult(rs, prependPrefix(innerResultMapping.getColumn(), columnPrefix));
      // issue #353 & #560 do not execute nested query if key is null
      if (propValue != null) {
        metaObject.setValue(innerResultMapping.getProperty(), propValue);
        foundValues = true;
      }
    }
    return foundValues ? parameterObject : null;
  }

  /**
   * 17、实例化参数对象，如果为null则构造HashMap
   * @param parameterType
   * @return
   */
  private Object instantiateParameterObject(Class<?> parameterType) {
    if (parameterType == null) {
      return new HashMap<>();
    } else {
      return objectFactory.create(parameterType);
    }
  }

  /**
   * 16.1.1.1、为嵌套查询准备参数-单一键
   * @param rs
   * @param resultMapping
   * @param parameterType
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object prepareSimpleKeyParameter(ResultSet rs, ResultMapping resultMapping, Class<?> parameterType, String columnPrefix) throws SQLException {
    final TypeHandler<?> typeHandler;
    if (typeHandlerRegistry.hasTypeHandler(parameterType)) {
      typeHandler = typeHandlerRegistry.getTypeHandler(parameterType);
    } else {
      typeHandler = typeHandlerRegistry.getUnknownTypeHandler();
    }
    return typeHandler.getResult(rs, prependPrefix(resultMapping.getColumn(), columnPrefix));
  }


  /**
   * 17、判断resultMap是否开启自动映射,resultMap节点有这属性,不配置的话为null
   * @param resultMap
   * @param isNested
   * @return
   */
  private boolean shouldApplyAutomaticMappings(ResultMap resultMap, boolean isNested) {
    if (resultMap.getAutoMapping() != null) {
      return resultMap.getAutoMapping();
    } else {
      if (isNested) {
        return AutoMappingBehavior.FULL == configuration.getAutoMappingBehavior();
      } else {
        return AutoMappingBehavior.NONE != configuration.getAutoMappingBehavior();
      }
    }
  }

  /**
   * 18、对象已经初始化,如果开启了自动映射则走这里进行属性的设置
   * @param rsw
   * @param resultMap
   * @param metaObject
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private boolean applyAutomaticMappings(ResultSetWrapper rsw, ResultMap resultMap, MetaObject metaObject, String columnPrefix) throws SQLException {
    // 1、获取ResultSet中未配置映射的字段
    final List<String> unmappedColumnNames = rsw.getUnmappedColumnNames(resultMap, columnPrefix);
    boolean foundValues = false;
    // 2、遍历
    for (String columnName : unmappedColumnNames) {
      // a、选处理下属性名,把数据库字段的前缀去掉
      String propertyName = columnName;
      if (columnPrefix != null && !columnPrefix.isEmpty()) {
        if (columnName.toUpperCase(Locale.ENGLISH).startsWith(columnPrefix)) {
          propertyName = columnName.substring(columnPrefix.length());
        } else {
          continue;
        }
      }
      // b、这里去查属性名 (这里体现出驼峰设置了，如果设置成true,那么会自动将user_name转化成username)
      final String property = metaObject.findProperty(propertyName, configuration.isMapUnderscoreToCamelCase());
      // c、查到属性名,继续
      if (property != null && metaObject.hasSetter(property)) {
        final Class<?> propertyType = metaObject.getSetterType(property);
        // d、类型处理器注册表有该属性的处理器,继续
        if (typeHandlerRegistry.hasTypeHandler(propertyType)) {
          final TypeHandler<?> typeHandler = rsw.getTypeHandler(propertyType, columnName);
          // I、用TypeHandler取得结果
          final Object value = typeHandler.getResult(rsw.getResultSet(), columnName);
          // II 赋值   (如果value是null,那需要判断Configuration中是否允许设置null值,且需要判断是否是基本类型)
          if (value != null || configuration.isCallSettersOnNulls()) {
            if (value != null || !propertyType.isPrimitive()) {
              metaObject.setValue(property, value);
            }
            foundValues = true;
          }
        }
      }
    }
    // 3、只要有一个未配置映射的字段映射成功,foundValues即为true
    return foundValues;
  }

  /**
   * 19、执行属性映射,给对象赋值
   * @param rsw
   * @param resultMap
   * @param metaObject
   * @param lazyLoader
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private boolean applyPropertyMappings(ResultSetWrapper rsw, ResultMap resultMap, MetaObject metaObject, ResultLoaderMap lazyLoader, String columnPrefix) throws SQLException {
    // 1、取得所有配置了映射的字段和resultMap中所有的普通属性映射
    final List<String> mappedColumnNames = rsw.getMappedColumnNames(resultMap, columnPrefix);
    final List<ResultMapping> propertyMappings = resultMap.getPropertyResultMappings();
    boolean foundValues = false;
    // 2、遍历propertyMappings
    for (ResultMapping propertyMapping : propertyMappings) {
      // a、给propertyMapping中的字段名加上前缀
      final String column = prependPrefix(propertyMapping.getColumn(), columnPrefix);
      // b、如果propertyMapping是复合节点,或者propertyMapping配置了结果集，最次是mappedColumnNames存在该字段
      if (propertyMapping.isCompositeResult() || (column != null && mappedColumnNames.contains(column.toUpperCase(Locale.ENGLISH))) || propertyMapping.getResultSet() != null) {
        // c、返回对应字段的查询结果
        Object value = getPropertyMappingValue(rsw.getResultSet(), metaObject, propertyMapping, lazyLoader, columnPrefix);
        final String property = propertyMapping.getProperty();
        if (value != NO_VALUE && property != null && (value != null || configuration.isCallSettersOnNulls())) {
          if (value != null || !metaObject.getSetterType(property).isPrimitive()) {
            // d、value不是NO_VALUE则给结果对象设置属性
            metaObject.setValue(property, value);
          }
          foundValues = true;
        }
      }
    }
    return foundValues;
  }

  /**
   * 20、获取Property对应的查询结果
   * @param rs
   * @param metaResultObject
   * @param propertyMapping
   * @param lazyLoader
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object getPropertyMappingValue(ResultSet rs, MetaObject metaResultObject, ResultMapping propertyMapping, ResultLoaderMap lazyLoader, String columnPrefix) throws SQLException {
    if (propertyMapping.getNestedQueryId() != null) {
      // 1、如果内嵌了查询语句,走这里
      return getNestedQueryMappingValue(rs, metaResultObject, propertyMapping, lazyLoader, columnPrefix);
    } else if (propertyMapping.getResultSet() != null) {
      // 2、如果指定了结果集，走这里
      addPendingChildRelation(rs, metaResultObject, propertyMapping);
      return NO_VALUE;
    } else if (propertyMapping.getNestedResultMapId() != null) {
      // 3、如果既没指定内嵌语句，也没指定结果集,但指定了ResultMapId,那直接返回NO_VALUE
      return NO_VALUE;
    } else {
      // 4、啥都没指定走这里,返回对应字段的查询结果
      final TypeHandler<?> typeHandler = propertyMapping.getTypeHandler();
      final String column = prependPrefix(propertyMapping.getColumn(), columnPrefix);
      return typeHandler.getResult(rs, column);
    }
  }

  /**
   * 21、获取内嵌sql的查询结果
   * @param rs
   * @param metaResultObject
   * @param propertyMapping
   * @param lazyLoader
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  private Object getNestedQueryMappingValue(ResultSet rs, MetaObject metaResultObject, ResultMapping propertyMapping, ResultLoaderMap lazyLoader, String columnPrefix) throws SQLException {
    // 1、查出内嵌的查询语句ID
    final String nestedQueryId = propertyMapping.getNestedQueryId();
    final String property = propertyMapping.getProperty();
    final MappedStatement nestedQuery = configuration.getMappedStatement(nestedQueryId);
    final Class<?> nestedQueryParameterType = nestedQuery.getParameterMap().getType();
    // 2、为嵌套查询准备参数
    final Object nestedQueryParameterObject = prepareParameterForNestedQuery(rs, propertyMapping, nestedQueryParameterType, columnPrefix);

    Object value = NO_VALUE;
    // 3、进行嵌套查询,如果配置了延迟加载，那就放到延迟加载器中去
    if (nestedQueryParameterObject != null) {
      final BoundSql nestedBoundSql = nestedQuery.getBoundSql(nestedQueryParameterObject);
      final CacheKey key = executor.createCacheKey(nestedQuery, nestedQueryParameterObject, RowBounds.DEFAULT, nestedBoundSql);
      final Class<?> targetType = propertyMapping.getJavaType();

      if (executor.isCached(nestedQuery, key)) {
        // a、根据当前key去缓存中查询,如果能查到缓存,就直接加载
        executor.deferLoad(nestedQuery, metaResultObject, property, key, targetType);
      } else {
        // b、如果缓存中没有,则使用内置sql加载器
        final ResultLoader resultLoader = new ResultLoader(configuration, executor, nestedQuery, nestedQueryParameterObject, targetType, key, nestedBoundSql);
        if (propertyMapping.isLazy()) {
          // I、如果当前ResultMapping配置了延迟加载,那就添加进lazyLoader
          lazyLoader.addLoader(property, metaResultObject, resultLoader);
        } else {
          // II、如果没配置延迟加载,直接查出结果
          value = resultLoader.loadResult();
        }
      }
    }
    // 4、返回结果(不一定有结果)
    return value;
  }

  /**
   * 22、把ResultMapping梳理下存到pendingRelations和nextResultMaps里
   *
   * 一般只有association节点才会配置resultSet
   *       <association property="author" javaType="Author" resultSet="authors" column="author_id" foreignColumn="id">
   *         <id property="id" column="id"/>
   *         <result property="username" column="username"/>
   *         <result property="password" column="password"/>
   *         <result property="email" column="email"/>
   *         <result property="bio" column="bio"/>
   *       </association>
   * @param rs
   * @param metaResultObject
   * @param parentMapping
   * @throws SQLException
   */
  private void addPendingChildRelation(ResultSet rs, MetaObject metaResultObject, ResultMapping parentMapping) throws SQLException {
    // 1、创建当前ResultMapping相关的缓存键
    CacheKey cacheKey = createKeyForMultipleResults(rs, parentMapping, parentMapping.getColumn(), parentMapping.getColumn());
    // 2、创建PendingRelation对象,维护metaResultObject和ResultMapping
    PendingRelation deferLoad = new PendingRelation();
    deferLoad.metaObject = metaResultObject;
    deferLoad.propertyMapping = parentMapping;
    // 3、往Map<CacheKey, List<PendingRelation>>里存元素
    List<PendingRelation> relations = pendingRelations.get(cacheKey);
    if (relations == null) {
      relations = new ArrayList<>();
      pendingRelations.put(cacheKey, relations);
    }
    relations.add(deferLoad);
    // 4、往Map<String, ResultMapping>里存元素，key为ResultSetName,value为当前ResultMapping
    ResultMapping previous = nextResultMaps.get(parentMapping.getResultSet());
    if (previous == null) {
      nextResultMaps.put(parentMapping.getResultSet(), parentMapping);
    } else {
      if (!previous.equals(parentMapping)) {
        throw new ExecutorException("Two different properties are mapped to the same resultSet");
      }
    }
  }

  /**
   * 23、为多结果resultMapping创建缓存键
   * @param rs
   * @param resultMapping
   * @param names
   * @param columns
   * @return
   * @throws SQLException
   */
  private CacheKey createKeyForMultipleResults(ResultSet rs, ResultMapping resultMapping, String names, String columns) throws SQLException {
    CacheKey cacheKey = new CacheKey();
    // 1、第一个变量,resultMapping对象
    cacheKey.update(resultMapping);

    if (columns != null && names != null) {
      String[] columnsArray = columns.split(",");
      String[] namesArray = names.split(",");

      for (int i = 0 ; i < columnsArray.length ; i++) {
        Object value = rs.getString(columnsArray[i]);
        if (value != null) {
          // 2、第二个变量,name和value
          cacheKey.update(namesArray[i]);
          cacheKey.update(value);
        }
      }
    }
    return cacheKey;
  }

  /**
   *  静态内部类：维护多resultSet情况下的不同的结果对象和ResultMapping的对应关系
   */
  private static class PendingRelation {
    public MetaObject metaObject;
    public ResultMapping propertyMapping;
  }

  /**
   * 存储当前行转化的对象
   * @param resultHandler   结果处理器
   * @param resultContext   结果上下文
   * @param rowValue        当前行数据转化的对象
   * @param parentMapping    ??
   * @param rs              ResultSet
   * @throws SQLException
   */
  private void storeObject(ResultHandler resultHandler, DefaultResultContext resultContext, Object rowValue, ResultMapping parentMapping, ResultSet rs) throws SQLException {
    if (parentMapping != null) {
      linkToParents(rs, parentMapping, rowValue);
    } else {
      callResultHandler(resultHandler, resultContext, rowValue);
    }
  }

  /**
   * ???
   * @param rs
   * @param parentMapping
   * @param rowValue
   * @throws SQLException
   */
  private void linkToParents(ResultSet rs, ResultMapping parentMapping, Object rowValue) throws SQLException {
    CacheKey parentKey = createKeyForMultipleResults(rs, parentMapping, parentMapping.getColumn(), parentMapping.getForeignColumn());
    List<PendingRelation> parents = pendingRelations.get(parentKey);
    for (PendingRelation parent : parents) {
      if (parent != null) {
        final Object collectionProperty = instantiateCollectionPropertyIfAppropriate(parent.propertyMapping, parent.metaObject);
        if (rowValue != null) {
          if (collectionProperty != null) {
            final MetaObject targetMetaObject = configuration.newMetaObject(collectionProperty);
            targetMetaObject.add(rowValue);
          } else {
            parent.metaObject.setValue(parent.propertyMapping.getProperty(), rowValue);
          }
        }
      }
    }
  }

  /**
   * 处理结果
   * @param resultHandler
   * @param resultContext
   * @param rowValue
   */
  private void callResultHandler(ResultHandler resultHandler, DefaultResultContext resultContext, Object rowValue) {
    // 1、自增1  (控制行数)
    resultContext.nextResultObject(rowValue);
    // 2、处理结果(一般是DefaultResultHandler,会将对象存储到内部的集合容器中)
    resultHandler.handleResult(resultContext);
  }

  /**
   * 获取下一个结果集
   * @param stmt
   * @return
   */
  private ResultSetWrapper getNextResultSet(Statement stmt) {
    try {
      // 检索该数据库是否支持从单个连接获取多个ResultSet对象,假如能拿到第二个ResultSet,那就包装下返回
      if (stmt.getConnection().getMetaData().supportsMultipleResultSets()) {
        if (!((!stmt.getMoreResults()) && (stmt.getUpdateCount() == -1))) {
          ResultSet rs = stmt.getResultSet();
          return rs != null ? new ResultSetWrapper(rs, configuration) : null;
        }else{}

      }
    } catch (Exception e) {}
    return null;
  }

  /**
   * 带有嵌套结果映射的映射语句不能被定制化的RowBounds安全地约束,如果非要用，就必须设置safeRowBoundsEnabled=false
   */
  private void ensureNoRowBounds() {
    if (configuration.isSafeRowBoundsEnabled() && rowBounds != null && (rowBounds.getLimit() < RowBounds.NO_ROW_LIMIT || rowBounds.getOffset() > RowBounds.NO_ROW_OFFSET)) {
      throw new ExecutorException("Mapped Statements with nested result mappings cannot be safely constrained by RowBounds.Use safeRowBoundsEnabled=false setting to bypass this check.");
    }
  }

  /**
   * 嵌套的resultMap使用定制化的resultHandler不安全,如果非得使用,要么设置safeResultHandlerEnabled=false,要么设置映射语句为有序的
   */
  protected void checkResultHandler() {
    if (resultHandler != null && configuration.isSafeResultHandlerEnabled() && !mappedStatement.isResultOrdered()) {
      throw new ExecutorException("Mapped Statements with nested result mappings cannot be safely used with a custom ResultHandler. " + "Use safeResultHandlerEnabled=false setting to bypass this check " + "or ensure your statement returns ordered data and set resultOrdered=true on it.");
    }
  }



  /**
   * 关闭resultSet
   * @param rs
   */
  private void closeResultSet(ResultSet rs) {
    try {
      if (rs != null) {
        rs.close();
      }
    } catch (SQLException e) {}
  }



  private void cleanUpAfterHandlingResultSet() {
    nestedResultObjects.clear();
    ancestorColumnPrefix.clear();
  }

  @SuppressWarnings("unchecked")
  private List<Object> collapseSingleResultList(List<Object> multipleResults) {
    return multipleResults.size() == 1 ? (List<Object>) multipleResults.get(0) : multipleResults;
  }

  private Object instantiateCollectionPropertyIfAppropriate(ResultMapping resultMapping, MetaObject metaObject) {
    final String propertyName = resultMapping.getProperty();
    Object propertyValue = metaObject.getValue(propertyName);
    if (propertyValue == null) {
      Class<?> type = resultMapping.getJavaType();
      if (type == null) {
        type = metaObject.getSetterType(propertyName);
      }
      try {
        if (objectFactory.isCollection(type)) {
          propertyValue = objectFactory.create(type);
          metaObject.setValue(propertyName, propertyValue);
          return propertyValue;
        }
      } catch (Exception e) {
        throw new ExecutorException("Error instantiating collection property for result '" + resultMapping.getProperty() + "'.  Cause: " + e, e);
      }
    } else if (objectFactory.isCollection(propertyValue.getClass())) {
      return propertyValue;
    }
    return null;
  }


  private boolean applyNestedResultMappings(ResultSetWrapper rsw, ResultMap resultMap, MetaObject metaObject, String parentPrefix, CacheKey parentRowKey, boolean newObject) {
    boolean foundValues = false;
    for (ResultMapping resultMapping : resultMap.getPropertyResultMappings()) {
      final String nestedResultMapId = resultMapping.getNestedResultMapId();
      if (nestedResultMapId != null && resultMapping.getResultSet() == null) {
        try {
          final String columnPrefix = getColumnPrefix(parentPrefix, resultMapping);
          final ResultMap nestedResultMap = getNestedResultMap(rsw.getResultSet(), nestedResultMapId, columnPrefix);
          CacheKey rowKey = null;
          Object ancestorObject = null;
          if (ancestorColumnPrefix.containsKey(nestedResultMapId)) {
            rowKey = createRowKey(nestedResultMap, rsw, ancestorColumnPrefix.get(nestedResultMapId));
            ancestorObject = ancestorObjects.get(rowKey);
          }
          if (ancestorObject != null) {
            if (newObject) {
              metaObject.setValue(resultMapping.getProperty(), ancestorObject);
            }
          } else {
            rowKey = createRowKey(nestedResultMap, rsw, columnPrefix);
            final CacheKey combinedKey = combineKeys(rowKey, parentRowKey);
            Object rowValue = nestedResultObjects.get(combinedKey);
            boolean knownValue = (rowValue != null);
            final Object collectionProperty = instantiateCollectionPropertyIfAppropriate(resultMapping, metaObject);
            if (anyNotNullColumnHasValue(resultMapping, columnPrefix, rsw.getResultSet())) {
              rowValue = getRowValue(rsw, nestedResultMap, combinedKey, rowKey, columnPrefix, rowValue);
              if (rowValue != null && !knownValue) {
                if (collectionProperty != null) {
                  final MetaObject targetMetaObject = configuration.newMetaObject(collectionProperty);
                  targetMetaObject.add(rowValue);
                } else {
                  metaObject.setValue(resultMapping.getProperty(), rowValue);
                }
                foundValues = true;
              }
            }
          }
        } catch (SQLException e) {
          throw new ExecutorException("Error getting nested result map values for '" + resultMapping.getProperty() + "'.  Cause: " + e, e);
        }
      }
    }
    return foundValues;
  }

  private String getColumnPrefix(String parentPrefix, ResultMapping resultMapping) {
    final StringBuilder columnPrefixBuilder = new StringBuilder();
    if (parentPrefix != null) {
      columnPrefixBuilder.append(parentPrefix);
    }
    if (resultMapping.getColumnPrefix() != null) {
      columnPrefixBuilder.append(resultMapping.getColumnPrefix());
    }
    return columnPrefixBuilder.length() == 0 ? null : columnPrefixBuilder.toString().toUpperCase(Locale.ENGLISH);
  }

  private boolean anyNotNullColumnHasValue(ResultMapping resultMapping, String columnPrefix, ResultSet rs) throws SQLException {
    Set<String> notNullColumns = resultMapping.getNotNullColumns();
    boolean anyNotNullColumnHasValue = true;
    if (notNullColumns != null && !notNullColumns.isEmpty()) {
      anyNotNullColumnHasValue = false;
      for (String column: notNullColumns) {
        rs.getObject(prependPrefix(column, columnPrefix));
        if (!rs.wasNull()) {
          anyNotNullColumnHasValue = true;
          break;
        }
      }
    }
    return anyNotNullColumnHasValue;
  }

  private ResultMap getNestedResultMap(ResultSet rs, String nestedResultMapId, String columnPrefix) throws SQLException {
    ResultMap nestedResultMap = configuration.getResultMap(nestedResultMapId);
    return resolveDiscriminatedResultMap(rs, nestedResultMap, columnPrefix);
  }

  private CacheKey combineKeys(CacheKey rowKey, CacheKey parentRowKey) {
    if (rowKey.getUpdateCount() > 1 && parentRowKey.getUpdateCount() > 1) {
      CacheKey combinedKey;
      try {
        combinedKey = rowKey.clone();
      } catch (CloneNotSupportedException e) {
        throw new ExecutorException("Error cloning cache key.  Cause: " + e, e);
      }
      combinedKey.update(parentRowKey);
      return combinedKey;
    }
    return CacheKey.NULL_CACHE_KEY;
  }


}
