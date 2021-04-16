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
package org.apache.ibatis.session;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Properties;

import org.apache.ibatis.builder.xml.XMLConfigBuilder;
import org.apache.ibatis.exceptions.ExceptionFactory;
import org.apache.ibatis.executor.ErrorContext;
import org.apache.ibatis.session.defaults.DefaultSqlSessionFactory;

/**
 *
 * 构建SqlSessionFactory的工厂.
 * 核心的是前三个,后面的都是重载方法。
 *@author Clinton Begin
 */
public class SqlSessionFactoryBuilder {

  /**
   *   第一种方法使用Reader获取配置信息，它使用了一个参照了XML文档或更特定的SqlMapConfig.xml文件的Reader实例。
   *   可选的参数是environment和properties。Environment决定加载哪种环境(开发环境/生产环境)，包括数据源和事务管理器。
   *   如果使用properties，那么就会加载那些properties（属性配置文件），那些属性可以用${propName}语法形式多次用在配置文件中。
   * @return SqlSessionFactory
   */
  /**
   * 第一种方法
   * @param reader XML文档或更SqlMapConfig.xml文件的Reader实例。
   * @param environment 哪种环境(开发环境/生产环境)，包括数据源和事务管理器。
   * @param properties 属性配置文件
   * @return SqlSessionFactory
   */
  public SqlSessionFactory build(Reader reader, String environment, Properties properties) {
    try {
      //1、委托XMLConfigBuilder来解析xml文件，并构建
      XMLConfigBuilder parser = new XMLConfigBuilder(reader, environment, properties);
      // 2、调build(Configuration config)
      return build(parser.parse());
    } catch (Exception e) {
      // 1.1、报错直接抛出异常
      throw ExceptionFactory.wrapException("Error building SqlSession.", e);
    } finally {
      // 1.2、重置下ErrorContext
      ErrorContext.instance().reset();
      try {
        // 3、关闭资源
        reader.close();
      } catch (IOException ignored) {
      }
    }
  }

  /**
   * 第2种方法，Reader换成了InputStream
   * @return SqlSessionFactory
   */
  public SqlSessionFactory build(InputStream inputStream, String environment, Properties properties) {
    try {
      XMLConfigBuilder parser = new XMLConfigBuilder(inputStream, environment, properties);
      return build(parser.parse());
    } catch (Exception e) {
      throw ExceptionFactory.wrapException("Error building SqlSession.", e);
    } finally {
      ErrorContext.instance().reset();
      try {
        inputStream.close();
      } catch (IOException e) {
        // Intentionally ignore. Prefer previous error.
      }
    }
  }

  /**
   * 第3种方法, 核心方法
   * 这是最重要的方法,既被方法1和方法2调用，同时也可以直接由用户调用，入参是Configuration，所以从这里看出来上面两个方法是为了生成Configuration
   * 返回的是默认的会话工厂DefaultSqlSessionFactory
   * @return SqlSessionFactory
   */
  public SqlSessionFactory build(Configuration config) {
    return new DefaultSqlSessionFactory(config);
  }

  // 下面的6个方法都是对方法1和方法2的重载

  public SqlSessionFactory build(Reader reader) { return build(reader, null, null);}

  public SqlSessionFactory build(Reader reader, String environment) {return build(reader, environment, null);}

  public SqlSessionFactory build(Reader reader, Properties properties) {return build(reader, null, properties);}

  public SqlSessionFactory build(InputStream inputStream) {return build(inputStream, null, null);}

  public SqlSessionFactory build(InputStream inputStream, String environment) {return build(inputStream, environment, null);}

  public SqlSessionFactory build(InputStream inputStream, Properties properties) { return build(inputStream, null, properties);}


}
