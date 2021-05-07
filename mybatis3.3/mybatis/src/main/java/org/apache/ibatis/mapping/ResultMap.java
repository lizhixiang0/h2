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
package org.apache.ibatis.mapping;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.apache.ibatis.session.Configuration;

/**
 *  结果集合,可以理解为ResultMap节点解析后得到的类
 *  MyBatis 中最重要最强大的元素
 * @author Clinton Begin
 */
public class ResultMap {
  private String id;
  /**
   *
   */
  private Class<?> type;
  /**
   * 总的属性映射容器,外面构建好传递进来的
   */
  private List<ResultMapping> resultMappings;
  /**
   * 存放id相关的属性映射容器
   */
  private List<ResultMapping> idResultMappings;
  /**
   * 存在类的构造器属性映射容器 （区别在于此类属性可以通过创建对象时进行复制）
   */
  private List<ResultMapping> constructorResultMappings;
  /**
   * 存放类的普通属性映射容器
   */
  private List<ResultMapping> propertyResultMappings;
  /**
   * 映射的列名集合
   */
  private Set<String> mappedColumns;
  /**
   * 鉴别器（默认为null）,控制结果映射器向不同的结果映射
   */
  private Discriminator discriminator;
  /**
   * 判断当前ResultMap是否存在内嵌的ResultMap
   */
  private boolean hasNestedResultMaps;

  private boolean hasNestedQueries;
  /**
   * 自动映射
   */
  private Boolean autoMapping;

  /**
   * 构造私有化,配合建造者
   */
  private ResultMap() {
  }

  /**
   * 静态内部类，建造者模式
   */
  public static class Builder {
    /**
     * 内部维护了一个resultMap
     */
    private ResultMap resultMap = new ResultMap();

    /**
     * 重载的构造方法1
     * @param configuration 核心配置类
     * @param id resultMap的唯一标识
     * @param type resultMap对应的java类
     * @param resultMappings resultMap节点下的所有resultMapping
     */
    public Builder(Configuration configuration, String id, Class<?> type, List<ResultMapping> resultMappings) {
      this(configuration, id, type, resultMappings, null);
    }

    /**
     * 重载的构造方法2
     * @param configuration 核心配置类
     * @param id resultMap的唯一标识
     * @param type  resultMap对应的java类
     * @param resultMappings resultMap节点下的所有resultMapping
     * @param autoMapping  是否自动映射
     */
    public Builder(Configuration configuration, String id, Class<?> type, List<ResultMapping> resultMappings, Boolean autoMapping) {
      resultMap.id = id;
      resultMap.type = type;
      resultMap.resultMappings = resultMappings;
      resultMap.autoMapping = autoMapping;
    }

    public Builder discriminator(Discriminator discriminator) {
      resultMap.discriminator = discriminator;
      return this;
    }

    public Class<?> type() {
      return resultMap.type;
    }

    /**
     * 核心方法,构建ResultMap
     */
    public ResultMap build() {
      // 1、如果resultMap的唯一标识为null ,直接报错
      if (resultMap.id == null) {
        throw new IllegalArgumentException("ResultMaps must have an id");
      }
      // 2、初始化resultMap的四个容器对象
      resultMap.mappedColumns = new HashSet<>();
      resultMap.idResultMappings = new ArrayList<>();
      resultMap.constructorResultMappings = new ArrayList<>();
      resultMap.propertyResultMappings = new ArrayList<>();
      // 3、循环遍历ResultMapping,将信息分装到不同的容器中去
      for (ResultMapping resultMapping : resultMap.resultMappings) {
        // a、只要有一条resultMapping内嵌查询语句，就设置该ResultMapping内嵌了查询语句
        resultMap.hasNestedQueries = resultMap.hasNestedQueries || resultMapping.getNestedQueryId() != null;
        // b、只要有一条resultMapping内嵌ResultMap,设置该ResultMapping内嵌了ResultMap
        resultMap.hasNestedResultMaps = resultMap.hasNestedResultMaps || (resultMapping.getNestedResultMapId() != null && resultMapping.getResultSet() == null);
        // c、获得列名,将映射的列名存到映射列名集合容器
        final String column = resultMapping.getColumn();
        if (column != null) {
          // c1、如果column不为null,则说明不是复合列名,那就直接转为大写后添加到mappedColumns
          resultMap.mappedColumns.add(column.toUpperCase(Locale.ENGLISH));
        } else if (resultMapping.isCompositeResult()) {
          // c2、如果column为null ,则可能是复合列名,判断下,如果确实是,遍历其composites,然后将列名都添加到mappedColumns中
          for (ResultMapping compositeResultMapping : resultMapping.getComposites()) {
            final String compositeColumn = compositeResultMapping.getColumn();
            if (compositeColumn != null) {
              resultMap.mappedColumns.add(compositeColumn.toUpperCase(Locale.ENGLISH));
            }
          }
        }
        // d、如果resultMapping存在CONSTRUCTOR,将其添加到构造器结果映射容器里,如果不存在，就将其添加到属性结果映射容器里
        if (resultMapping.getFlags().contains(ResultFlag.CONSTRUCTOR)) {
          resultMap.constructorResultMappings.add(resultMapping);
        } else {
          resultMap.propertyResultMappings.add(resultMapping);
        }
        // e、如果resultMapping存在ID,将其将其添加到ID结果映射容器里
        if (resultMapping.getFlags().contains(ResultFlag.ID)) {
          resultMap.idResultMappings.add(resultMapping);
        }
      }
      // 4、循环处理完resultMappings后，如果idResultMappings为空,就将所有resultMappings都添加进idResultMappings
      if (resultMap.idResultMappings.isEmpty()) {
        resultMap.idResultMappings.addAll(resultMap.resultMappings);
      }
      // 5、锁定所有集合,将其变为不可变集合对象
      resultMap.resultMappings = Collections.unmodifiableList(resultMap.resultMappings);
      resultMap.idResultMappings = Collections.unmodifiableList(resultMap.idResultMappings);
      resultMap.constructorResultMappings = Collections.unmodifiableList(resultMap.constructorResultMappings);
      resultMap.propertyResultMappings = Collections.unmodifiableList(resultMap.propertyResultMappings);
      resultMap.mappedColumns = Collections.unmodifiableSet(resultMap.mappedColumns);
      // 6、处理完后,返回resultMap
      return resultMap;
    }
  }

  public String getId() {
    return id;
  }

  public boolean hasNestedResultMaps() {
    return hasNestedResultMaps;
  }

  public boolean hasNestedQueries() {
    return hasNestedQueries;
  }

  public Class<?> getType() {
    return type;
  }

  public List<ResultMapping> getResultMappings() {
    return resultMappings;
  }

  public List<ResultMapping> getConstructorResultMappings() {
    return constructorResultMappings;
  }

  public List<ResultMapping> getPropertyResultMappings() {
    return propertyResultMappings;
  }

  public List<ResultMapping> getIdResultMappings() {
    return idResultMappings;
  }

  public Set<String> getMappedColumns() {
    return mappedColumns;
  }

  public Discriminator getDiscriminator() {
    return discriminator;
  }

  public void forceNestedResultMaps() {
    hasNestedResultMaps = true;
  }

  public Boolean getAutoMapping() {
    return autoMapping;
  }

}
