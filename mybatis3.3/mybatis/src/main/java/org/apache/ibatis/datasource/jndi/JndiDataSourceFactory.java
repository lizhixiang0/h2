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
package org.apache.ibatis.datasource.jndi;

import java.util.Map.Entry;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.ibatis.datasource.DataSourceException;
import org.apache.ibatis.datasource.DataSourceFactory;

/**
 * JNDI数据源工厂 (java naming directory interface | java命名目录接口)
 * 类似于在一个中心注册一个东西，以后要用的时候，只需要根据名字去注册中心查找，注册中心返回你要的东西
 * 目的为了使用如 Spring 或应用服务器这类的容器, 可以在容器配置数据源,然后放置一个 JNDI 上下文的引用。
 * 这一块的内容等将来研究spring-mybatis是来搞。
 * @blog "https://www.jianshu.com/p/ad4c16e0b8ba
 * @author Clinton Begin
 */
public class JndiDataSourceFactory implements DataSourceFactory {
  /**
   * 起始上下文标识
   */
  public static final String INITIAL_CONTEXT = "initial_context";
  /**
   * 数据源标识
   */
  public static final String DATA_SOURCE = "data_source";

  /**
   * 和其他数据源配置相似, 它也可以通过名为 "env." 的前缀直接向初始上下文发送属性。 比如:env.encoding=UTF8
   */
  public static final String ENV_PREFIX = "env.";

  private DataSource dataSource;

  @Override
  public DataSource getDataSource() {
    return dataSource;
  }

  @Override
  public void setProperties(Properties properties) {
    try {
      // 1、创建起始上下文，可以理解成注册中心
      InitialContext initCtx = null;
      Properties env = getEnvProperties(properties);
      if (env == null) {
        initCtx = new InitialContext();
      } else {
        initCtx = new InitialContext(env);
      }
      // 2、从注册中心拿到数据源
      if (properties.containsKey(INITIAL_CONTEXT)&& properties.containsKey(DATA_SOURCE)) {
        Context ctx = (Context) initCtx.lookup(properties.getProperty(INITIAL_CONTEXT));
        dataSource = (DataSource) ctx.lookup(properties.getProperty(DATA_SOURCE));
      } else if (properties.containsKey(DATA_SOURCE)) {
        dataSource = (DataSource) initCtx.lookup(properties.getProperty(DATA_SOURCE));
      }
    } catch (NamingException e) {
      throw new DataSourceException("There was an error configuring JndiDataSourceTransactionPool. Cause: " + e, e);
    }
  }

  /**
   * 和其他数据源工厂的处理方式一致，都是去掉属性名的前缀然后塞到Properties里
   */
  private static Properties getEnvProperties(Properties allProps) {
    final String PREFIX = ENV_PREFIX;
    Properties contextProperties = null;
    for (Entry<Object, Object> entry : allProps.entrySet()) {
      String key = (String) entry.getKey();
      String value = (String) entry.getValue();
      if (key.startsWith(PREFIX)) {
        if (contextProperties == null) {
          contextProperties = new Properties();
        }
        contextProperties.put(key.substring(PREFIX.length()), value);
      }
    }
    return contextProperties;
  }

}
