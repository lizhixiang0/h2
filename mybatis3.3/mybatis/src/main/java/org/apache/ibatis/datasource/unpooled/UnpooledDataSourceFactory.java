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
package org.apache.ibatis.datasource.unpooled;

import java.util.Properties;

import javax.sql.DataSource;

import org.apache.ibatis.datasource.DataSourceException;
import org.apache.ibatis.datasource.DataSourceFactory;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.SystemMetaObject;

/**
 * 非池化的数据源工厂
 * @author Clinton Begin
 */
public class UnpooledDataSourceFactory implements DataSourceFactory {
  /**
   * 数据库驱动前缀
   */
  private static final String DRIVER_PROPERTY_PREFIX = "driver.";
  private static final int DRIVER_PROPERTY_PREFIX_LENGTH = DRIVER_PROPERTY_PREFIX.length();

  /**
   * 对应的数据源，即 非池化的数据源
   */
  protected DataSource dataSource;

  /**
   * 初始化工厂时就实例化了一个非池化的数据源
   */
  public UnpooledDataSourceFactory() {
    // 注意：池化工厂使用的是无参构造
    this.dataSource = new UnpooledDataSource();
  }

  /**
   * 对数据源进行配置
   * @param properties 各类属性,数据以<k,v>形式存储
   */
  @Override
  public void setProperties(Properties properties) {
    // 1、创建一个HashTable
    Properties driverProperties = new Properties();
    // 2、创建解析数据源对象,生成MetaObject
    MetaObject metaDataSource = SystemMetaObject.forObject(dataSource);
    // 3、循环遍历properties,将适合的放到driverProperties里
    for (Object key : properties.keySet()) {
      // 3.1、拿到属性名
      String propertyName = (String) key;
      // 3.2、如果属性名是以"driver."开头的,去掉前缀后直接塞到driverProperties里,例如：driver.encoding=UTF8
      if (propertyName.startsWith(DRIVER_PROPERTY_PREFIX)) {
        String value = properties.getProperty(propertyName);
        driverProperties.setProperty(propertyName.substring(DRIVER_PROPERTY_PREFIX_LENGTH), value);
        // 3.3、如果属性名是不以"driver."开头,则判断dataSource中是否有该属性,有的话转化下value类型也塞到driverProperties里
      } else if (metaDataSource.hasSetter(propertyName)) {
        String value = (String) properties.get(propertyName);
        Object convertedValue = convertValue(metaDataSource, propertyName, value);
        metaDataSource.setValue(propertyName, convertedValue);
      } else {
        throw new DataSourceException("Unknown DataSource property: " + propertyName);
      }
    }
    // 4、如果driverProperties不为空,set进dataSource
    if (driverProperties.size() > 0) {
      metaDataSource.setValue("driverProperties", driverProperties);
    }
  }

  /**
   * 根据setter的类型,将配置文件中的值强转成相应的类型
   * @param metaDataSource 元类
   * @param propertyName 属性名
   * @param value 属性值
   * @return
   */
  private Object convertValue(MetaObject metaDataSource, String propertyName, String value) {
    Object convertedValue = value;
    // 1、找到dataSource中相应属性的类型
    Class<?> targetType = metaDataSource.getSetterType(propertyName);
    // 2、转换
    if (targetType == Integer.class || targetType == int.class) {
      convertedValue = Integer.valueOf(value);
    } else if (targetType == Long.class || targetType == long.class) {
      convertedValue = Long.valueOf(value);
    } else if (targetType == Boolean.class || targetType == boolean.class) {
      convertedValue = Boolean.valueOf(value);
    }
    // 3、返回
    return convertedValue;
  }

  @Override
  public DataSource getDataSource() {
    return dataSource;
  }

}
