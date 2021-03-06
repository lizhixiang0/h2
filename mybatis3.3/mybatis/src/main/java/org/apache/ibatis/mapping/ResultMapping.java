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
package org.apache.ibatis.mapping;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeHandler;
import org.apache.ibatis.type.TypeHandlerRegistry;

/**
 * 结果映射,代表了一个属性和列名的对应关系
 * <id property="id" column="id"/>
 * <result property="title" column="title"/>
 * <association property="author" javaType="Author" resultSet="authors" column="author_id" foreignColumn="id">
 * <collection property="posts" ofType="Post">
 *
 *
 *     <select id="selectBlog" resultSets="blogs,authors" resultMap="blogResult" statementType="CALLABLE">
 *      {call getBlogsAndAuthors(#{id,jdbcType=INTEGER,mode=IN})}
 *     </select>
 *
 *     <resultMap id="blogResult" type="Blog">
 *      <id property="id" column="id" />
 *      <result property="title" column="title"/>
 *
 *    ` <association property="author" javaType="Author" resultSet="authors" column="author_id" foreignColumn="id">
 *       <id property="id" column="id"/>
 *       <result property="username" column="username"/>
 *       <result property="password" column="password"/>
 *       <result property="email" column="email"/>
 *       <result property="bio" column="bio"/>
 *      </association>
 *     </resultMap>
 *
 * @author Clinton Begin
 */
public class ResultMapping {

  private Configuration configuration;
  private String property;
  /**
   * 配置的列名
   */
  private String column;
  private Class<?> javaType;
  private JdbcType jdbcType;
  private TypeHandler<?> typeHandler;
  /**
   * 内嵌的ResultMap
   */
  private String nestedResultMapId;
  /**
   * 内嵌的查询语句
   */
  private String nestedQueryId;
  /**
   * 必须不为null的列
   */
  private Set<String> notNullColumns;
  /**
   * 用来区分同名列的前缀
   */
  private String columnPrefix;
  /**
   * 结果标记
   * 如果当前节点有ID属性，则此集合会有ResultFlag.ID
   * 如果当前节点的父节点为<constructor>,则此集合会有ResultFlag.CONSTRUCTOR
   */
  private List<ResultFlag> flags;
  /**
   * 可以使用 column="{prop1=col1,prop2=col2}" 这样的语法来传递多个参数给内嵌Select查询语句
   * 如果当前节点存在复合列名,则根据复合列名的对应关系,生成List<ResultMapping>
   */
  private List<ResultMapping> composites;
  /**
   * 当前节点指定的结果集
   * 如果存在多个结果集,先在映射语句中通过resultSets属性为每个结果集指定一个名字,然后在关联节点里指定对应的结果集
   */
  private String resultSet;
  /**
   * 多结果集下，结果集中用于与外键匹配的列
   */
  private String foreignColumn;
  /**
   * 是否懒加载,单个的ResultMapping配置拦加载？？
   */
  private boolean lazy;

  private ResultMapping() {
  }

  public static class Builder {
    private ResultMapping resultMapping = new ResultMapping();

    public Builder(Configuration configuration, String property, String column, TypeHandler<?> typeHandler) {
      this(configuration, property);
      resultMapping.column = column;
      resultMapping.typeHandler = typeHandler;
    }

    public Builder(Configuration configuration, String property, String column, Class<?> javaType) {
      this(configuration, property);
      resultMapping.column = column;
      resultMapping.javaType = javaType;
    }

    public Builder(Configuration configuration, String property) {
      resultMapping.configuration = configuration;
      resultMapping.property = property;
      resultMapping.flags = new ArrayList<>();
      resultMapping.composites = new ArrayList<>();
      resultMapping.lazy = configuration.isLazyLoadingEnabled();
    }

    public Builder javaType(Class<?> javaType) {
      resultMapping.javaType = javaType;
      return this;
    }

    public Builder jdbcType(JdbcType jdbcType) {
      resultMapping.jdbcType = jdbcType;
      return this;
    }

    public Builder nestedResultMapId(String nestedResultMapId) {
      resultMapping.nestedResultMapId = nestedResultMapId;
      return this;
    }

    public Builder nestedQueryId(String nestedQueryId) {
      resultMapping.nestedQueryId = nestedQueryId;
      return this;
    }

    public Builder resultSet(String resultSet) {
      resultMapping.resultSet = resultSet;
      return this;
    }

    public Builder foreignColumn(String foreignColumn) {
      resultMapping.foreignColumn = foreignColumn;
      return this;
    }

    public Builder notNullColumns(Set<String> notNullColumns) {
      resultMapping.notNullColumns = notNullColumns;
      return this;
    }

    public Builder columnPrefix(String columnPrefix) {
      resultMapping.columnPrefix = columnPrefix;
      return this;
    }

    public Builder flags(List<ResultFlag> flags) {
      resultMapping.flags = flags;
      return this;
    }

    public Builder typeHandler(TypeHandler<?> typeHandler) {
      resultMapping.typeHandler = typeHandler;
      return this;
    }

    public Builder composites(List<ResultMapping> composites) {
      resultMapping.composites = composites;
      return this;
    }

    public Builder lazy(boolean lazy) {
      resultMapping.lazy = lazy;
      return this;
    }

    /**
     * 建造者的核心方法
     */
    public ResultMapping build() {
      // 1、锁定集合flags和composites为不可变集合
      resultMapping.flags = Collections.unmodifiableList(resultMapping.flags);
      resultMapping.composites = Collections.unmodifiableList(resultMapping.composites);
      // 2、配置类型处理器
      resolveTypeHandler();
      // 3、一些验证
      validate();
      // 4、返回resultMapping
      return resultMapping;
    }

    /**
     * 获取类型处理器,只要javaType不为null,就能找到
     */
    private void resolveTypeHandler() {
      if (resultMapping.typeHandler == null && resultMapping.javaType != null) {
        Configuration configuration = resultMapping.configuration;
        TypeHandlerRegistry typeHandlerRegistry = configuration.getTypeHandlerRegistry();
        resultMapping.typeHandler = typeHandlerRegistry.getTypeHandler(resultMapping.javaType, resultMapping.jdbcType);
      }
    }

    private void validate() {
      // 不能同时定义nestedQueryId和nestedResultMapId
      if (resultMapping.nestedQueryId != null && resultMapping.nestedResultMapId != null) {
        throw new IllegalStateException("Cannot define both nestedQueryId and nestedResultMapId in property " + resultMapping.property);
      }
      // 如果没有内嵌sql和ResultMap,那typeHandler必须存在
      if (resultMapping.nestedQueryId == null && resultMapping.nestedResultMapId == null && resultMapping.typeHandler == null) {
        throw new IllegalStateException("No typeHandler found for property " + resultMapping.property);
      }
      // 内嵌ResultMap和column至少配置一个
      if (resultMapping.nestedResultMapId == null && resultMapping.column == null && resultMapping.composites.isEmpty()) {
        throw new IllegalStateException("Mapping is missing column attribute for property " + resultMapping.property);
      }
      // 如果配置了resultSet，应该有相同数量的列和外键列
      if (resultMapping.getResultSet() != null) {
        int columns = 0;
        if (resultMapping.column != null) {
          columns = resultMapping.column.split(",").length;
        }
        int numForeignColumns = 0;
        if (resultMapping.foreignColumn != null) {
          numForeignColumns = resultMapping.foreignColumn.split(",").length;
        }
        if (columns != numForeignColumns) {
          throw new IllegalStateException("There should be the same number of columns and foreignColumns in property " + resultMapping.property);
        }
      }
    }

    public Builder column(String column) {
      resultMapping.column = column;
      return this;
    }
  }

  public String getProperty() {
    return property;
  }

  public String getColumn() {
    return column;
  }

  public Class<?> getJavaType() {
    return javaType;
  }

  public JdbcType getJdbcType() {
    return jdbcType;
  }

  public TypeHandler<?> getTypeHandler() {
    return typeHandler;
  }

  public String getNestedResultMapId() {
    return nestedResultMapId;
  }

  public String getNestedQueryId() {
    return nestedQueryId;
  }

  public Set<String> getNotNullColumns() {
    return notNullColumns;
  }

  public String getColumnPrefix() {
    return columnPrefix;
  }

  public List<ResultFlag> getFlags() {
    return flags;
  }

  public List<ResultMapping> getComposites() {
    return composites;
  }

  public boolean isCompositeResult() {
    return this.composites != null && !this.composites.isEmpty();
  }

  public String getResultSet() {
    return this.resultSet;
  }

  public String getForeignColumn() {
    return foreignColumn;
  }

  public void setForeignColumn(String foreignColumn) {
    this.foreignColumn = foreignColumn;
  }

  public boolean isLazy() {
    return lazy;
  }

  public void setLazy(boolean lazy) {
    this.lazy = lazy;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    ResultMapping that = (ResultMapping) o;

    if (property == null || !property.equals(that.property)) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    if (property != null) {
      return property.hashCode();
    } else if (column != null) {
      return column.hashCode();
    } else {
      return 0;
    }
  }

}
