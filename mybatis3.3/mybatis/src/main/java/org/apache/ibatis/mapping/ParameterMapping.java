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

import java.sql.ResultSet;

import lombok.Getter;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeHandler;
import org.apache.ibatis.type.TypeHandlerRegistry;

/**
 * 参数映射,这个"参数"是指传入SQL语句的参数
 * 1、对于大多数简单的使用场景，你都不需要使用复杂的参数，比如：
 *    <select id="selectUsers" resultType="User">
 *      select id, username, password
 *      from users
 *      where id = #{id}
 *    </select>
 *
 * 2、但是,参数也可以指定一个特殊的数据类型,例如：
 *    #{age,javaType=int,jdbcType=NUMERIC,typeHandler=MyTypeHandler}
 *
 * 3、对于数值类型，还可以设置 numericScale 指定小数点后保留的位数。例如：
 *    #{height,javaType=double,jdbcType=NUMERIC,numericScale=2}
 *
 * 4、还有mode 属性允许指定 IN，OUT 或 INOUT 参数。如果参数的 mode 为 OUT 或 INOUT，将会修改参数对象的属性值，以便作为输出参数返回。
 *    如果 mode 为 OUT（或 INOUT），而且 jdbcType 为 CURSOR（也就是 Oracle 的 REFCURSOR），
 *    必须指定一个 resultMap 引用来将结果集 ResultMap 映射到参数的类型上
 *    #{department, mode=OUT, jdbcType=CURSOR, javaType=ResultSet, resultMap=departmentResultMap}
 *
 * @author Clinton Begin
 * @note "http://www.mybatis.cn/archives/890.html
 */
@Getter
public class ParameterMapping {

  private Configuration configuration;

  /**
   * 属性
   */
  private String property;
  /**
   * 参数模式
   */
  private ParameterMode mode;
  /**
   * 参数的java类型
   */
  private Class<?> javaType = Object.class;
  /**
   * 参数的jdbc类型
   */
  private JdbcType jdbcType;
  /**
   * 参数的jdbc类型名
   */
  private String jdbcTypeName;
  /**
   * 参数的小数点后几位
   */
  private Integer numericScale;
  /**
   * 参数类型处理器
   */
  private TypeHandler<?> typeHandler;
  /**
   * 指定的resultMap引用
   */
  private String resultMapId;
  /**
   * 表达式？？
   */
  private String expression;

  private ParameterMapping() {
  }

  /**
   * 静态内部类，建造者模式
   */
  public static class Builder {
    private ParameterMapping parameterMapping = new ParameterMapping();

    /**
     * 第一个构造器
     * @param configuration 核心配置类
     * @param property  属性
     * @param typeHandler  类型处理器
     */
    public Builder(Configuration configuration, String property, TypeHandler<?> typeHandler) {
      parameterMapping.configuration = configuration;
      parameterMapping.property = property;
      parameterMapping.typeHandler = typeHandler;
      parameterMapping.mode = ParameterMode.IN;
    }

    /**
     * 第二个构造器
     * @param configuration 核心配置类
     * @param property 属性
     * @param javaType java类型
     */
    public Builder(Configuration configuration, String property, Class<?> javaType) {
      parameterMapping.configuration = configuration;
      parameterMapping.property = property;
      parameterMapping.javaType = javaType;
      parameterMapping.mode = ParameterMode.IN;
    }

    public Builder mode(ParameterMode mode) {
      parameterMapping.mode = mode;
      return this;
    }

    public Builder javaType(Class<?> javaType) {
      parameterMapping.javaType = javaType;
      return this;
    }

    public Builder jdbcType(JdbcType jdbcType) {
      parameterMapping.jdbcType = jdbcType;
      return this;
    }

    public Builder numericScale(Integer numericScale) {
      parameterMapping.numericScale = numericScale;
      return this;
    }

    public Builder resultMapId(String resultMapId) {
      parameterMapping.resultMapId = resultMapId;
      return this;
    }

    public Builder typeHandler(TypeHandler<?> typeHandler) {
      parameterMapping.typeHandler = typeHandler;
      return this;
    }

    public Builder jdbcTypeName(String jdbcTypeName) {
      parameterMapping.jdbcTypeName = jdbcTypeName;
      return this;
    }

    public Builder expression(String expression) {
      parameterMapping.expression = expression;
      return this;
    }

    /**
     * 核心build方法
     * @return parameterMapping
     */
    public ParameterMapping build() {
      resolveTypeHandler();
      validate();
      return parameterMapping;
    }

    /**
     * 防止没配置类型处理器,这里会根据javaType、jdbcType 来查注册表确定一个默认的typeHandler,有没有可能找不到？
     */
    private void resolveTypeHandler() {
      if (parameterMapping.typeHandler == null && parameterMapping.javaType != null) {
        Configuration configuration = parameterMapping.configuration;
        TypeHandlerRegistry typeHandlerRegistry = configuration.getTypeHandlerRegistry();
        // 主要是根据java类型去类型处理器注册表中找对应的处理器
        parameterMapping.typeHandler = typeHandlerRegistry.getTypeHandler(parameterMapping.javaType, parameterMapping.jdbcType);
      }
    }

    /**
     * 最后检测
     */
    private void validate() {
      // 1、如果javaType是ResultSet,那必须配置resultMap
      if (ResultSet.class.equals(parameterMapping.javaType)) {
        if (parameterMapping.resultMapId == null) {
          throw new IllegalStateException("Missing resultmap in property '"+ parameterMapping.property + "'.  "+ "Parameters of type java.sql.ResultSet require a resultmap.");
        }
      } else {
        // 2、如果javaType不是ResultSet,那必须配置typeHandler
        if (parameterMapping.typeHandler == null) {
          throw new IllegalStateException("Type handler was null on parameter mapping for property '"+ parameterMapping.property + "'.  "+ "It was either not specified and/or could not be found for the javaType / jdbcType combination specified.");
        }
      }
    }
  }
}
