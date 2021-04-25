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

/**
 * 类型处理器
 * @author Clinton Begin
 * @note "https://zhuanlan.zhihu.com/p/245448322
 * @note "https://www.jianshu.com/p/6172c7f6e27e
 * @note "https://blog.csdn.net/u012702547/article/details/54572679
 */
public interface TypeHandler<T> {

  /**
   * 设置参数，将java类型转换为jdbc类型
   * @param ps ？？
   * @param i ？？
   * @param parameter 参数
   * @param jdbcType  jdbc类型
   * @throws SQLException
   */
  void setParameter(PreparedStatement ps, int i, T parameter, JdbcType jdbcType) throws SQLException;

  /**
   * 根据columnName取出结果集中当前行的数据
   * @param rs 结果集
   * @param columnName 字段名
   * @return
   * @throws SQLException
   */
  T getResult(ResultSet rs, String columnName) throws SQLException;

  /**
   * 从ResultSet中拿到主键值
   * @param rs 结果集
   * @param columnIndex 字段索引
   */
  T getResult(ResultSet rs, int columnIndex) throws SQLException;

  /**
   * 将查询的结果转换为java类型 （存储过程）
   * @param cs
   * @param columnIndex 字段索引
   * @return
   * @throws SQLException
   */
  T getResult(CallableStatement cs, int columnIndex) throws SQLException;

}
