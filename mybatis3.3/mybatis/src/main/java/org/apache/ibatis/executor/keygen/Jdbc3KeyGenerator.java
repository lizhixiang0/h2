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
package org.apache.ibatis.executor.keygen;

import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.ExecutorException;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.type.TypeHandler;
import org.apache.ibatis.type.TypeHandlerRegistry;

/**
 * JDBC3键值生成器,核心是使用JDBC3的Statement.getGeneratedKeys
 * @author Clinton Begin
 */
public class Jdbc3KeyGenerator implements KeyGenerator {

  @Override
  public void processBefore(Executor executor, MappedStatement ms, Statement stmt, Object parameter) {
    // do nothing
  }

  @Override
  public void processAfter(Executor executor, MappedStatement ms, Statement stmt, Object parameter) {
    List<Object> parameters = new ArrayList<>();
    parameters.add(parameter);
    processBatch(ms, stmt, parameters);
  }

  /**
   * 批处理,因为可能插入大量的数据
   * @param ms
   * @param stmt
   * @param parameters
   */
  public void processBatch(MappedStatement ms, Statement stmt, List<Object> parameters) {
    ResultSet rs = null;
    try {
      // 1、获得赋值主键的属性名数组
      final Configuration configuration = ms.getConfiguration();
      final TypeHandlerRegistry typeHandlerRegistry = configuration.getTypeHandlerRegistry();
      final String[] keyProperties = ms.getKeyProperties();
      // 2、获得主键结果集
      rs = stmt.getGeneratedKeys();
      // 3、得到结果集(rs)的结构信息，比如字段名等。
      final ResultSetMetaData rsmd = rs.getMetaData();

      TypeHandler<?>[] typeHandlers = null;
      // 4、比较结果集的列数是否大于属性名数组
      if (keyProperties != null && rsmd.getColumnCount() >= keyProperties.length) {

        // 5、循环遍历参数值
        for (Object parameter : parameters) {
          // a、游标,必须存在数值才进行操作
          if (!rs.next()) {
            break;
          }
          final MetaObject metaParam = configuration.newMetaObject(parameter);
          if (typeHandlers == null) {
            //b、先取得类型处理器
            typeHandlers = getTypeHandlers(typeHandlerRegistry, metaParam, keyProperties);
          }
          // c、填充键值
          populateKeys(rs, metaParam, keyProperties, typeHandlers);
        }
      }
    } catch (Exception e) {
      throw new ExecutorException("Error getting generated key or setting result to parameter object. Cause: " + e, e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (Exception e) {}
      }
    }
  }

  /**
   * 获得类型处理器数组
   * @param typeHandlerRegistry   类型处理器表
   * @param metaParam  参数元对象
   * @param keyProperties   主键属性数组
   * @return
   */
  private TypeHandler<?>[] getTypeHandlers(TypeHandlerRegistry typeHandlerRegistry, MetaObject metaParam, String[] keyProperties) {
    // 1、创建类型处理器数组
    TypeHandler<?>[] typeHandlers = new TypeHandler<?>[keyProperties.length];
    // 2、遍历主键属性数组
    for (int i = 0; i < keyProperties.length; i++) {
      if (metaParam.hasSetter(keyProperties[i])) {
        Class<?> keyPropertyType = metaParam.getSetterType(keyProperties[i]);
        TypeHandler<?> th = typeHandlerRegistry.getTypeHandler(keyPropertyType);
        typeHandlers[i] = th;
      }
    }
    return typeHandlers;
  }

  /**
   * 填充主键
   * @param rs
   * @param metaParam  参数对象
   * @param keyProperties  主键数组
   * @param typeHandlers 主键对应的类型处理器
   * @throws SQLException
   */
  private void populateKeys(ResultSet rs, MetaObject metaParam, String[] keyProperties, TypeHandler<?>[] typeHandlers) throws SQLException {
    // 遍历主键数组
    for (int i = 0; i < keyProperties.length; i++) {
      // 获得主键对应的类型处理器
      TypeHandler<?> th = typeHandlers[i];
      if (th != null) {
        // 拿到主键值
        Object value = th.getResult(rs, i + 1);
        // 设置到参数对象中
        metaParam.setValue(keyProperties[i], value);
      }
    }
  }

}
