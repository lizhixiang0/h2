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
package org.apache.ibatis.executor.resultset;

import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.ObjectTypeHandler;
import org.apache.ibatis.type.TypeHandler;
import org.apache.ibatis.type.TypeHandlerRegistry;
import org.apache.ibatis.type.UnknownTypeHandler;

/**
 * @author Iwao AVE!
 */
class ResultSetWrapper {

  private final ResultSet resultSet;
  /**
   * mybatis的类型处理器注册表
   */
  private final TypeHandlerRegistry typeHandlerRegistry;
  /**
   * 存储字段名
   */
  private final List<String> columnNames = new ArrayList<>();
  /**
   * 存储字段的JdbcType类型
   */
  private final List<JdbcType> jdbcTypes = new ArrayList<>();
  /**
   * 存储字段对应的Java类的完全限定名称
   */
  private final List<String> classNames = new ArrayList<>();

  /**
   * typeHandlerMap.put(columnName, columnHandlers);   // string表示columnName,columnHandlers表示的是当前columnName对应的java类所对应的类型处理器
   * 例如：Java中的String可能转换成JAVA的char、varchar等多种类型，所以存在一对多的关系，所以值要用Map来存储
   */
  private final Map<String, Map<Class<?>, TypeHandler<?>>> typeHandlerMap = new HashMap<>();

  /**
   * 查询出来的resultSet中的字段,不一定能在一个resultMap找到所有的映射,这两个容器用来记录
   * string表示resultMapID
   */
  private Map<String, List<String>> mappedColumnNamesMap = new HashMap<>();
  private Map<String, List<String>> unMappedColumnNamesMap = new HashMap<>();

  /**
   * 构造方法
   * @param rs  结果集
   * @param configuration   核心配置类
   * @throws SQLException
   */
  public ResultSetWrapper(ResultSet rs, Configuration configuration) throws SQLException {
    super();
    this.typeHandlerRegistry = configuration.getTypeHandlerRegistry();
    this.resultSet = rs;
    // 1、检索此ResultSet对象的列的数量、类型和属性
    final ResultSetMetaData metaData = rs.getMetaData();
    // 2、获得此ResultSet对象的列的数量
    final int columnCount = metaData.getColumnCount();
    // 3、遍历处理ResultSet的数据结构(此时并没有处理数据)
    for (int i = 1; i <= columnCount; i++) {
      columnNames.add(configuration.isUseColumnLabel() ? metaData.getColumnLabel(i) : metaData.getColumnName(i));
      jdbcTypes.add(JdbcType.forCode(metaData.getColumnType(i)));
      classNames.add(metaData.getColumnClassName(i));
    }
  }

  public ResultSet getResultSet() {
    return resultSet;
  }

  public List<String> getColumnNames() {
    return this.columnNames;
  }

  public List<String> getClassNames() {
    return Collections.unmodifiableList(classNames);
  }

  /**
   * 获取读取结果集时要使用的类型处理程序,尝试通过搜索属性类型从TypeHandlerRegistry获取。
   * 如果没有找到，它将获取列JDBC类型并尝试获取其处理程序。
   * @param propertyType   字段对应的java类型
   * @param columnName 字段名
   * @return
   */
  public TypeHandler<?> getTypeHandler(Class<?> propertyType, String columnName) {
    TypeHandler<?> handler = null;
    // 1、根据columnName找出类型处理器,第一次肯定是没有的
    Map<Class<?>, TypeHandler<?>> columnHandlers = typeHandlerMap.get(columnName);
    if (columnHandlers == null) {
      columnHandlers = new HashMap<>(16);
      typeHandlerMap.put(columnName, columnHandlers);
    } else {
      handler = columnHandlers.get(propertyType);
    }
    // 2、找不到类型处理器
    if (handler == null) {

      // a、根据Java类型从注册表中获取处理器,注册表里没有就构造一个
      handler = typeHandlerRegistry.getTypeHandler(propertyType);
      if (handler == null || handler instanceof UnknownTypeHandler) {
        final int index = columnNames.indexOf(columnName);
        final JdbcType jdbcType = jdbcTypes.get(index);
        final Class<?> javaType = resolveClass(classNames.get(index));
        if (javaType != null && jdbcType != null) {
          handler = typeHandlerRegistry.getTypeHandler(javaType, jdbcType);
        } else if (javaType != null) {
          handler = typeHandlerRegistry.getTypeHandler(javaType);
        } else if (jdbcType != null) {
          handler = typeHandlerRegistry.getTypeHandler(jdbcType);
        }
      }
      // b、是在拿不到处理器,构造objectTypeHandler(),这样取出的数据都是Object类型的
      if (handler == null || handler instanceof UnknownTypeHandler) {
        handler = new ObjectTypeHandler();
      }
      // c、最后将得到的处理器放到columnHandlers里,下次来访问就能直接拿了
      columnHandlers.put(propertyType, handler);
    }
    // 4、返回处理器
    return handler;
  }

  private Class<?> resolveClass(String className) {
    try {
      return Resources.classForName(className);
    } catch (ClassNotFoundException e) {
      return null;
    }
  }

  /**
   * 加载已映射和未映射列名
   * @param resultMap
   * @param columnPrefix
   */
  private void loadMappedAndUnmappedColumnNames(ResultMap resultMap, String columnPrefix) {
    // 1、创建两个容器,存放已映射的列和未映射的列
    List<String> mappedColumnNames = new ArrayList<>();
    List<String> unmappedColumnNames = new ArrayList<>();
    // 2、将前缀改为大写
    final String upperColumnPrefix = columnPrefix == null ? null : columnPrefix.toUpperCase(Locale.ENGLISH);
    // 3、从resultMap中获取所有列名,并加上前缀
    final Set<String> mappedColumns = prependPrefixes(resultMap.getMappedColumns(), upperColumnPrefix);
    // 4、遍历resultSet的所有字段名,将配置了映射的放到mappedColumnNames,没配置的放到unmappedColumnNames
    for (String columnName : columnNames) {
      final String upperColumnName = columnName.toUpperCase(Locale.ENGLISH);
      if (mappedColumns.contains(upperColumnName)) {
        mappedColumnNames.add(upperColumnName);
      } else {
        unmappedColumnNames.add(columnName);
      }
    }
    // 5、存储到Map容器中
    mappedColumnNamesMap.put(getMapKey(resultMap, columnPrefix), mappedColumnNames);
    unMappedColumnNamesMap.put(getMapKey(resultMap, columnPrefix), unmappedColumnNames);
  }

  /**
   * 根据resultMapId,取出当前resultSet中配置了ResultMapping的字段
   * @param resultMap
   * @param columnPrefix
   * @return
   * @throws SQLException
   */
  public List<String> getMappedColumnNames(ResultMap resultMap, String columnPrefix) throws SQLException {
    List<String> mappedColumnNames = mappedColumnNamesMap.get(getMapKey(resultMap, columnPrefix));
    if (mappedColumnNames == null) {
      loadMappedAndUnmappedColumnNames(resultMap, columnPrefix);
      mappedColumnNames = mappedColumnNamesMap.get(getMapKey(resultMap, columnPrefix));
    }
    return mappedColumnNames;
  }

  /**
   * 根据resultMapId,取出当前resultSet中未配置ResultMapping的字段 （如果开启了自动映射,即使不配置也可以实现映射）
   * @param resultMap
   * @param columnPrefix
   * @return
   */
  public List<String> getUnmappedColumnNames(ResultMap resultMap, String columnPrefix) {
    List<String> unMappedColumnNames = unMappedColumnNamesMap.get(getMapKey(resultMap, columnPrefix));
    if (unMappedColumnNames == null) {
      loadMappedAndUnmappedColumnNames(resultMap, columnPrefix);
      unMappedColumnNames = unMappedColumnNamesMap.get(getMapKey(resultMap, columnPrefix));
    }
    return unMappedColumnNames;
  }

  /**
   * 给resultMap的ID加个后缀
   * @param resultMap
   * @param columnPrefix
   * @return
   */
  private String getMapKey(ResultMap resultMap, String columnPrefix) {
    return resultMap.getId() + ":" + columnPrefix;
  }

  /**
   * 给所有列名加上前缀
   * @param columnNames
   * @param prefix
   * @return
   */
  private Set<String> prependPrefixes(Set<String> columnNames, String prefix) {
    if (columnNames == null || columnNames.isEmpty() || prefix == null || prefix.length() == 0) {
      return columnNames;
    }
    final Set<String> prefixed = new HashSet<>();
    for (String columnName : columnNames) {
      prefixed.add(prefix + columnName);
    }
    return prefixed;
  }

}
