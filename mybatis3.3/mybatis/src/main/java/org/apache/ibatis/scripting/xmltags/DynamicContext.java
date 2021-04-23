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

import java.util.HashMap;
import java.util.Map;

import ognl.OgnlContext;
import ognl.OgnlRuntime;
import ognl.PropertyAccessor;

import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.session.Configuration;

/**
 * 动态上下文,
 * 1、拼接动态sql的临时寄存器
 * 2、DynamicContext为POJO对象Map化提供了很好的借鉴,抹平了访问POJO和Map对象的差异.
 * @author Clinton Begin
 * @link "https://blog.csdn.net/lqzkcx3/article/details/78278026
 */
public class DynamicContext {
  /**
   * 在编写映射文件时, '${_parameter}','${_databaseId}'分别可以取到当前用户传入的参数, 以及当前执行的数据库类型
   */
  public static final String PARAMETER_OBJECT_KEY = "_parameter";
  public static final String DATABASE_ID_KEY = "_databaseId";
  /**
   * 这里面存储了参数值,可以直接通过get(参数名)的方式取出用户传递的参数值
   */
  private final ContextMap bindings;
  private final StringBuilder sqlBuilder = new StringBuilder();
  private int uniqueNumber = 0;

  static {
    // Ognl运行时环境在动态计算sql语句时,会按照ContextAccessor中描述的Map接口的方式来访问和读取ContextMap对象
    OgnlRuntime.setPropertyAccessor(ContextMap.class, new ContextAccessor());
  }

  public DynamicContext(Configuration configuration, Object parameterObject) {
    if (parameterObject != null && !(parameterObject instanceof Map)) {
      // 当传入的参数对象不是Map类型时，Mybatis会将传入的POJO对象用MetaObject对象来封装,然后用ContextMap包装起来,即用ContextMap的get方法包装 MetaObject对象的取值过程。
      MetaObject metaObject = configuration.newMetaObject(parameterObject);
      bindings = new ContextMap(metaObject);
    } else {
      // 如果是map类型
      bindings = new ContextMap(null);
    }
    bindings.put(PARAMETER_OBJECT_KEY, parameterObject);
    bindings.put(DATABASE_ID_KEY, configuration.getDatabaseId());
  }

  public Map<String, Object> getBindings() {
    return bindings;
  }

  public void bind(String name, Object value) {
    bindings.put(name, value);
  }

  public void appendSql(String sql) {
    sqlBuilder.append(sql);
    sqlBuilder.append(" ");
  }

  public String getSql() {
    return sqlBuilder.toString().trim();
  }

  public int getUniqueNumber() {
    return uniqueNumber++;
  }

  /**
   * 静态内部类一
   *   用于统一参数的访问方式(用Map接口方法来访问数据)
   */
  static class ContextMap extends HashMap<String, Object> {
    private static final long serialVersionUID = 2977601501966151582L;
    /**
     * 1、维护了一个元对象
     */
    private MetaObject parameterMetaObject;
    public ContextMap(MetaObject parameterMetaObject) {
      this.parameterMetaObject = parameterMetaObject;
    }

    /**
     * 2、重写了get方法
     * @param key
     * @return
     */
    @Override
    public Object get(Object key) {
      String strKey = (String) key;
      // a、先去map里找
      if (super.containsKey(strKey)) {
        return super.get(strKey);
      }

      // b、如果没找到,再用ognl表达式去取值,如person[0].birthdate.year
      if (parameterMetaObject != null) {
        return parameterMetaObject.getValue(strKey);
      }
      // c、始终无法取到, 直接返回null
      return null;
    }
  }

  /**
   * 静态内部类二
   * 实现了Ognl中的PropertyAccessor接口，为Ognl提供了如何使用ContextMap参数对象的说明
   */
  static class ContextAccessor implements PropertyAccessor {

    @Override
    public Object getProperty(Map context, Object target, Object name) {
      // 1、target为ContextMap,所以转换为Map
      Map map = (Map) target;
      // 2、这里调用的ContextMap覆写的get方法;也就是缓存的POJO中的属性对;
      Object result = map.get(name);
      // 3、这里不为null时, 说明用户传入的是POJO
      if (result != null) {
        return result;
      }
      // 直接拿取不到result,说明参数是map类型
      // 4、构造DynamicContext实例时,插入到ContextMap实例中的键值对:{ "_parameter" : parameterObject }
      Object parameterObject = map.get(PARAMETER_OBJECT_KEY);
      //用户显式传入的就是Map类型
      if (parameterObject instanceof Map) {
        return ((Map)parameterObject).get(name);
      }

      return null;
    }

    @Override
    public void setProperty(Map context, Object target, Object name, Object value) {
      Map<Object, Object> map = (Map<Object, Object>) target;
      map.put(name, value);
    }

    @Override
    public String getSourceAccessor(OgnlContext arg0, Object arg1, Object arg2) {
      return null;
    }

    @Override
    public String getSourceSetter(OgnlContext arg0, Object arg1, Object arg2) {
      return null;
    }
  }
}
