/*
 * Copyright 2012-2013 MyBatis.org.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ibatis.scripting;

import org.apache.ibatis.executor.parameter.ParameterHandler;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.parsing.XNode;
import org.apache.ibatis.scripting.defaults.DefaultParameterHandler;
import org.apache.ibatis.session.Configuration;

/**
 * 脚本语言驱动
 *
 * @author admin
 */
public interface LanguageDriver {

  /**
   * 创建参数处理器
   * @param mappedStatement sql映射语句
   * @param parameterObject 参数对象
   * @param boundSql sql中转站
   * @return ParameterHandler
   */
  ParameterHandler createParameterHandler(MappedStatement mappedStatement, Object parameterObject, BoundSql boundSql);

  /**
   * 创建SQL源码(mapper xml方式)
   * @param configuration 核心配置类
   * @param script sql语句节点
   * @param parameterType 参数类型
   * @return SqlSource
   */
  SqlSource createSqlSource(Configuration configuration, XNode script, Class<?> parameterType);

  /**
   * 创建SQL源码(注解方式)
   * @param configuration 核心配置类
   * @param script 注解内容
   * @param parameterType 参数类型
   * @return SqlSource
   */
  SqlSource createSqlSource(Configuration configuration, String script, Class<?> parameterType);

}
