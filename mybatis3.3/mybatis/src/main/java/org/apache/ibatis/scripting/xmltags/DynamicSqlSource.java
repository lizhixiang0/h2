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
package org.apache.ibatis.scripting.xmltags;

import java.util.Map;

import org.apache.ibatis.builder.SqlSourceBuilder;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.session.Configuration;

/**
 * 动态SQL源
 * @author Clinton Begin
 */
public class DynamicSqlSource implements SqlSource {

  private Configuration configuration;
  private SqlNode rootSqlNode;

  public DynamicSqlSource(Configuration configuration, SqlNode rootSqlNode) {
    this.configuration = configuration;
    this.rootSqlNode = rootSqlNode;
  }

  /**
   * 得到绑定的SQL
   * 在没有执行这个方法之前,动态sql还是拆分状态,执行完之后才真正成了sql语句
   * @param parameterObject 参数对象
   * @return BoundSql
   */
  @Override
  public BoundSql getBoundSql(Object parameterObject) {
    // 1、生成一个动态上下文
    DynamicContext context = new DynamicContext(configuration, parameterObject);
    // 2、拼接动态sql,最终拼接好的sql存储在DynamicContext的sqlBuilder里
    rootSqlNode.apply(context);
	// 3、创建SqlSourceBuilder
    SqlSourceBuilder sqlSourceParser = new SqlSourceBuilder(configuration);
    // 4、获取参数类型
    Class<?> parameterType = parameterObject == null ? Object.class : parameterObject.getClass();
	// 5、执行SqlSourceBuilder.parse,替换sql中的#{xx}为"?",此时SqlSource是StaticSqlSource
    SqlSource sqlSource = sqlSourceParser.parse(context.getSql(), parameterType, context.getBindings());
	// 6、调用getBoundSql,因为此时是StaticSqlSource,所以得到BoundSql,此时都处理完毕
    BoundSql boundSql = sqlSource.getBoundSql(parameterObject);
    // 7、将context中存储的参数值都存放到boundSql的临时参数容器中
    for (Map.Entry<String, Object> entry : context.getBindings().entrySet()) {
      boundSql.setAdditionalParameter(entry.getKey(), entry.getValue());
    }
    // 8、返回boundSql
    return boundSql;
  }

}
