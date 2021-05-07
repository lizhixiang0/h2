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
package org.apache.ibatis.executor.loader;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.executor.BaseExecutor;
import org.apache.ibatis.executor.BatchResult;
import org.apache.ibatis.executor.ExecutorException;
import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

/**
 * 延迟加载容器,用来存储需要懒加载的属性，本质是一个HashMap
 * @author Clinton Begin
 * @author Franta Mejta
 */
public class ResultLoaderMap {
  /**
   *  key是property,value是LoadPair
   */
  private final Map<String, LoadPair> loaderMap = new HashMap<>();

  /**
   * 把要延迟加载的属性记到loaderMap里
   * @param property 属性
   * @param metaResultObject 结果元对象
   * @param resultLoader 内置sql加载器
   */
  public void addLoader(String property, MetaObject metaResultObject, ResultLoader resultLoader) {
    String upperFirst = getUppercaseFirstProperty(property);
    // 1、已经添加过的不允许再添加
    if (!upperFirst.equalsIgnoreCase(property) && loaderMap.containsKey(upperFirst)) {
      throw new ExecutorException("Nested lazy loaded result property '" + property +"' for query id '" + resultLoader.mappedStatement.getId() +" already exists in the result map. The leftmost property of all lazy loaded properties must be unique within a result map.");
    }
    // 2、构建LoadPair,存入loaderMap集合,key是upperFirst,value是LoadPair
    loaderMap.put(upperFirst, new LoadPair(property, metaResultObject, resultLoader));
  }

  public final Map<String, LoadPair> getProperties() {
    return new HashMap<>(this.loaderMap);
  }

  public Set<String> getPropertyNames() {
    return loaderMap.keySet();
  }

  public int size() {
    return loaderMap.size();
  }

  /**
   * 判断某属性是否是延迟加载属性
   */
  public boolean hasLoader(String property) {
    return loaderMap.containsKey(property.toUpperCase(Locale.ENGLISH));
  }

  public boolean load(String property) throws SQLException {
	// 1、取出后从删除  (加载过的就不是延迟加载属性了)
    LoadPair pair = loaderMap.remove(property.toUpperCase(Locale.ENGLISH));
    if (pair != null) {
      // 2、去数据库查
      pair.load();
      return true;
    }
    return false;
  }

  /**
   * 加载所有属性
   * @throws SQLException
   */
  public void loadAll() throws SQLException {
    final Set<String> methodNameSet = loaderMap.keySet();
    String[] methodNames = methodNameSet.toArray(new String[methodNameSet.size()]);
    for (String methodName : methodNames) {
      load(methodName);
    }
  }

  /**
   * 获取大写第一属性
   * person.name ----> PERSON
   * @param property
   * @return
   */
  private static String getUppercaseFirstProperty(String property) {
    String[] parts = property.split("\\.");
    return parts[0].toUpperCase(Locale.ENGLISH);
  }

  /**
   * 静态内部类,用来包装延迟加载的属性,load方法提供访问数据库的能力
   */
  public static class LoadPair implements Serializable {

    private static final long serialVersionUID = 20130412;

    private transient Log log;

    /**
     * 延迟加载的属性名
     */
    private String property;

    /**
     * 返回数据库连接的工厂方法的名称
     */
    private static final String FACTORY_METHOD = "getConfiguration";
    /**
     * 检查我们是否进行了序列化的对象,transient这个玩意儿序列化是透明的
     */
    private final transient Object serializationCheck = new Object();
    /**
     * 执行sql后生成的元对象,其中某些属性是延迟加载的
     */
    private transient MetaObject metaResultObject;
    /**
     * 加载未读属性的结果加载器。这玩意儿负责与数据库连接，执行sql语句，完成延迟属性的加载
     */
    private transient ResultLoader resultLoader;

    /**
     * 工厂类，通过它我们获得数据库连接。
     */
    private Class<?> configurationFactory;

    /**
     * SQL映射语句的ID
     */
    private String mappedStatement;
    /**
     * sql语句的参数。
     */
    private Serializable mappedParameter;


    /**
     * 私有构造方法,只能供本类使用
     * @param property   属性名
     * @param metaResultObject   结果元对象
     * @param resultLoader  内置sql加载器
     */
    private LoadPair(final String property, MetaObject metaResultObject, ResultLoader resultLoader) {
      this.property = property;
      this.metaResultObject = metaResultObject;
      this.resultLoader = resultLoader;

      // 1、原始对象需要实现序列化
      if (metaResultObject != null && metaResultObject.getOriginalObject() instanceof Serializable) {
        final Object mappedStatementParameter = resultLoader.parameterObject;
        // 参数对象需要实现序列化  (这里提一下,String这种包装类型是实现了序列化的)
        if (mappedStatementParameter instanceof Serializable) {
          this.mappedStatement = resultLoader.mappedStatement.getId();
          this.mappedParameter = (Serializable) mappedStatementParameter;
          this.configurationFactory = resultLoader.configuration.getConfigurationFactory();
        } else {
          this.getLogger().debug("Property [" + this.property + "] of [" + metaResultObject.getOriginalObject().getClass() + "] cannot be loaded " + "after deserialization. Make sure it's loaded before serializing " + "forenamed object.");
        }
      }
    }

    /**
     * 验证下
     * @throws SQLException
     */
    public void load() throws SQLException {
      if (this.metaResultObject == null) {
        throw new IllegalArgumentException("metaResultObject is null");
      }
      if (this.resultLoader == null) {
        throw new IllegalArgumentException("resultLoader is null");
      }
      this.load(null);
    }


    public void load(final Object userObject) throws SQLException {
      if (this.metaResultObject == null || this.resultLoader == null) {
        // 1、如果参数对象不实现序列化,这里就gg
        if (this.mappedParameter == null) {
          throw new ExecutorException("Property [" + this.property + "] cannot be loaded because " + "required parameter of mapped statement ["+ this.mappedStatement + "] is not serializable.");
        }
        // 2、获取Configuration
        final Configuration config = this.getConfiguration();
        final MappedStatement ms = config.getMappedStatement(this.mappedStatement);
        if (ms == null) {
          throw new ExecutorException("Cannot lazy load property [" + this.property+ "] of deserialized object [" + userObject.getClass()+ "] because configuration does not contain statement ["+ this.mappedStatement + "]");
        }
        this.metaResultObject = config.newMetaObject(userObject);
        // 2、这里又创建了一个resultLoader
        this.resultLoader = new ResultLoader(config, new ClosedExecutor(), ms, this.mappedParameter,metaResultObject.getSetterType(this.property), null, null);
      }

      /* We are using a new executor because we may be (and likely are) on a new thread
       * and executors aren't thread safe. (Is this sufficient?)
       *
       * A better approach would be making executors thread safe. */
      if (this.serializationCheck == null) {
        final ResultLoader old = this.resultLoader;
        this.resultLoader = new ResultLoader(old.configuration, new ClosedExecutor(), old.mappedStatement,old.parameterObject, old.targetType, old.cacheKey, old.boundSql);
      }

      this.metaResultObject.setValue(property, this.resultLoader.loadResult());
    }

    /**
     * 获取Configuration核心配置类
     * @return
     */
    private Configuration getConfiguration() {
      // 1、配置文件里必须设置configurationFactory
      if (this.configurationFactory == null) {
        throw new ExecutorException("Cannot get Configuration as configuration factory was not set.");
      }
      Object configurationObject = null;
      try {
        final Method factoryMethod = this.configurationFactory.getDeclaredMethod(FACTORY_METHOD);
        if (!Modifier.isStatic(factoryMethod.getModifiers())) {
          throw new ExecutorException("Cannot get Configuration as factory method ["+ this.configurationFactory + "]#["+ FACTORY_METHOD + "] is not static.");
        }

        if (!factoryMethod.isAccessible()) {
          configurationObject = AccessController.doPrivileged((PrivilegedExceptionAction<Object>) () -> {
            try {
              factoryMethod.setAccessible(true);
              return factoryMethod.invoke(null);
            } finally {
              factoryMethod.setAccessible(false);
            }
          });
        } else {
          configurationObject = factoryMethod.invoke(null);
        }
      } catch (final NoSuchMethodException ex) {
        throw new ExecutorException("Cannot get Configuration as factory class ["+ this.configurationFactory + "] is missing factory method of name ["+ FACTORY_METHOD + "].", ex);
      } catch (final PrivilegedActionException ex) {
        throw new ExecutorException("Cannot get Configuration as factory method ["+ this.configurationFactory + "]#["+ FACTORY_METHOD + "] threw an exception.", ex.getCause());
      } catch (final Exception ex) {
        throw new ExecutorException("Cannot get Configuration as factory method ["+ this.configurationFactory + "]#["+ FACTORY_METHOD + "] threw an exception.", ex);
      }
      if (!(configurationObject instanceof Configuration)) {
        throw new ExecutorException("Cannot get Configuration as factory method ["+ this.configurationFactory + "]#["+ FACTORY_METHOD + "] didn't return [" + Configuration.class + "] but ["+ (configurationObject == null ? "null" : configurationObject.getClass()) + "].");
      }
      return Configuration.class.cast(configurationObject);
    }

    private Log getLogger() {
      if (this.log == null) {
        this.log = LogFactory.getLog(this.getClass());
      }
      return this.log;
    }
  }

  /**
   * 静态内部类,不知道干啥的
   */
  private static final class ClosedExecutor extends BaseExecutor {

    public ClosedExecutor() {
      super(null, null);
    }

    @Override
    public boolean isClosed() {
      return true;
    }

    @Override
    protected int doUpdate(MappedStatement ms, Object parameter) {
      throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    protected List<BatchResult> doFlushStatements(boolean isRollback) {
      throw new UnsupportedOperationException("Not supported.");
    }

    @Override
    protected <E> List<E> doQuery(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler, BoundSql boundSql) throws SQLException {
      throw new UnsupportedOperationException("Not supported.");
    }
  }
}
