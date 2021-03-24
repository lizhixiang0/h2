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
package org.apache.ibatis.type;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.ibatis.session.Configuration;

/**
 * 类型处理Base类，典型的模板方法模式。
 * 实现了TypeHandler的方法，将异常捕获、null值处理的通用逻辑做了处理，具体真正的转换逻辑留给子类实现。
 * @author Clinton Begin
 */
public abstract class BaseTypeHandler<T> extends TypeReference<T> implements TypeHandler<T> {

  protected Configuration configuration;

  public void setConfiguration(Configuration c) {
    this.configuration = c;
  }

  @Override
  public void setParameter(PreparedStatement ps, int i, T parameter, JdbcType jdbcType) throws SQLException {
    // 1、参数为null自己处理
    if (parameter == null) {
      // 1.1、jdbcType也为null,直接报错
      if (jdbcType == null) {
        throw new TypeException("JDBC requires that the JdbcType must be specified for all nullable parameters.");
      }
      try {
        //1.2、jdbcType不为null,将指定参数设置为SQL NULL (Types.NULL)
        ps.setNull(i, jdbcType.TYPE_CODE);
      } catch (SQLException e) {
        throw new TypeException("Error setting null for parameter #" + i + " with JdbcType " + jdbcType + " . " +"Try setting a different JdbcType for this parameter or a different jdbcTypeForNull configuration property. " +"Cause: " + e, e);
      }
    } else {
      // 2、参数不为null 留给子类实现
      setNonNullParameter(ps, i, parameter, jdbcType);
    }
  }

  /**
   * 通过columnName从resultSet中取值，
   * 转换的类型根据子类来实现转换
   * @param rs 结果集
   * @param columnName column name, when configuration useColumnLabel is false
   */
  @Override
  public T getResult(ResultSet rs, String columnName) throws SQLException {
    T result = getNullableResult(rs, columnName);
    // 通过ResultSet.wasNull判断是否为NULL
    if (rs.wasNull()) {
      return null;
    } else {
      return result;
    }
  }

  @Override
  public T getResult(ResultSet rs, int columnIndex) throws SQLException {
    T result = getNullableResult(rs, columnIndex);
    if (rs.wasNull()) {
      return null;
    } else {
      return result;
    }
  }

  @Override
  public T getResult(CallableStatement cs, int columnIndex) throws SQLException {
    T result = getNullableResult(cs, columnIndex);
	//通过CallableStatement.wasNull判断是否为NULL
    if (cs.wasNull()) {
      return null;
    } else {
      return result;
    }
  }

  // 以下都是抽象方法,交由子类实现
  // 这个值得学习,基类实现了接口的方法，对一些特殊情况进行了处理，然后将核心方法外包给子类去实现，这样子类即使有问题也不担心

  public abstract void setNonNullParameter(PreparedStatement ps, int i, T parameter, JdbcType jdbcType) throws SQLException;

  public abstract T getNullableResult(ResultSet rs, String columnName) throws SQLException;

  public abstract T getNullableResult(ResultSet rs, int columnIndex) throws SQLException;

  public abstract T getNullableResult(CallableStatement cs, int columnIndex) throws SQLException;

}
