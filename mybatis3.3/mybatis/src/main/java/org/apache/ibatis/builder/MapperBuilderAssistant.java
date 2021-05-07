/*
 *    Copyright 2009-2014 the original author or authors.
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
package org.apache.ibatis.builder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.ibatis.cache.Cache;
import org.apache.ibatis.cache.decorators.LruCache;
import org.apache.ibatis.cache.impl.PerpetualCache;
import org.apache.ibatis.executor.ErrorContext;
import org.apache.ibatis.executor.keygen.KeyGenerator;
import org.apache.ibatis.mapping.CacheBuilder;
import org.apache.ibatis.mapping.Discriminator;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ParameterMap;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.mapping.ParameterMode;
import org.apache.ibatis.mapping.ResultFlag;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.mapping.ResultMapping;
import org.apache.ibatis.mapping.ResultSetType;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.mapping.StatementType;
import org.apache.ibatis.reflection.MetaClass;
import org.apache.ibatis.scripting.LanguageDriver;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeHandler;

/**
 * 映射构建器助手,一个XML映射解析器对应一个
 * @author Clinton Begin
 */
public class MapperBuilderAssistant extends BaseBuilder {
  /**
   * 命名空间（当前映射文件对应的dao接口全限定名）
   */
  private String currentNamespace;
  /**
   * 资源路径 （xml映射文件）
   */
  private String resource;
  /**
   * 表示当前xml的缓存
   */
  private Cache currentCache;
  /**
   * CacheRef是否解析完
   */
  private boolean unresolvedCacheRef;

  public MapperBuilderAssistant(Configuration configuration, String resource) {
    super(configuration);
    ErrorContext.instance().resource(resource);
    this.resource = resource;
  }

  public String getCurrentNamespace() {
    return currentNamespace;
  }

  public void setCurrentNamespace(String currentNamespace) {
    if (currentNamespace == null) {
      throw new BuilderException("The mapper element requires a namespace attribute to be specified.");
    }
    if (this.currentNamespace != null && !this.currentNamespace.equals(currentNamespace)) {
      throw new BuilderException("Wrong namespace. Expected '"+ this.currentNamespace + "' but found '" + currentNamespace + "'.");
    }
    this.currentNamespace = currentNamespace;
  }


  /**
   * 解析缓存引用
   * @param namespace 被引用的命名空间
   */
  public void useCacheRef(String namespace) {
    if (namespace == null) {
      throw new BuilderException("cache-ref element requires a namespace attribute.");
    }
    try {
      // 1、尚未解析
      unresolvedCacheRef = true;
      // 2、根据namespace从configuration里获取缓存, (这里不就有个问题么，如果引用的命名空间缓存还未加载，这里就么得，所以必须先加载被引用的xml咯？)
      Cache cache = configuration.getCache(namespace);
      if (cache == null) {
        throw new IncompleteElementException("No cache for namespace '" + namespace + "' could be found.");
      }
      // 3、将引用过来的缓存赋值给当前缓存
      currentCache = cache;
      // 4、解析结束
      unresolvedCacheRef = false;
    } catch (IllegalArgumentException e) {
      throw new IncompleteElementException("No cache for namespace '" + namespace + "' could be found.", e);
    }
  }

  /**
   * 创建缓存
   * @param typeClass       缓存类型
   * @param evictionClass   淘汰策略
   * @param flushInterval   冲刷间隔
   * @param size            缓存大小
   * @param readWrite       读写权限
   * @param blocking        是否阻塞
   * @param props           额外属性
   */
  public void useNewCache(Class<? extends Cache> typeClass,
                          Class<? extends Cache> evictionClass,
                          Long flushInterval,
                          Integer size,
                          boolean readWrite,
                          boolean blocking,
                          Properties props) {
    // 1、判断typeClass和evictionClass 是否为null,为null就用默认值
    typeClass = valueOrDefault(typeClass, PerpetualCache.class);
    evictionClass = valueOrDefault(evictionClass, LruCache.class);
    // 2、调用CacheBuilder构建cache,id=currentNamespace
    Cache cache = new CacheBuilder(currentNamespace)
        .implementation(typeClass)
        .addDecorator(evictionClass)
        .clearInterval(flushInterval)
        .size(size)
        .readWrite(readWrite)
        .blocking(blocking)
        .properties(props)
        .build();
    // 3、加入configuration中的缓存集中营
    configuration.addCache(cache);
    // 4、设置为当前的缓存   （这么说Cache和Cache-ref是互斥的？？）
    currentCache = cache;
  }

  /**
   * 给某些节点的ID加上namespace前缀
   * e.q. 如rowResult-->com.pax.com.rowResult
   * @param base 一般是各种节点的ID
   * @param isReference 是否允许base中有圆点
   */
  public String applyCurrentNamespace(String base, boolean isReference) {
    if (base == null) {
      return null;
    }
    if (isReference) {
      if (base.contains(".")) {
        // 1、允许有圆点,那有的话直接返回
        return base;
      }
    } else {
      if (base.startsWith(currentNamespace + ".")) {
        // 2、不允许有圆点,但是以命名空间.开头也直接返回,否则直接报错
        return base;
      }
      if (base.contains(".")) {
        throw new BuilderException("Dots are not allowed in element names, please remove it from " + base);
      }
    }
    // 3、没有圆点就加上currentNamespace.返回
    return currentNamespace + "." + base;
  }


  /**
   * 构建ParameterMapping
   * @param parameterType 属性所在类 || 元素所在容器类型
   * @param property      属性名
   * @param javaType      属性java类型
   * @param jdbcType      属性jdbc类型
   * @param resultMap     属性的resultMap  ？？？
   * @param parameterMode 属性的parameterMode ？？？
   * @param typeHandler   属性的类型处理器
   * @param numericScale  属性的小数点保留几位
   * @return ParameterMapping
   */
  public ParameterMapping buildParameterMapping(
      Class<?> parameterType,
      String property,
      Class<?> javaType,
      JdbcType jdbcType,
      String resultMap,
      ParameterMode parameterMode,
      Class<? extends TypeHandler<?>> typeHandler,
      Integer numericScale) {
    // 1、给resultMap加上名称空间作为前缀
    resultMap = applyCurrentNamespace(resultMap, true);
    // 2、有时候不写明java类型,所以得给定一个java类型
    Class<?> javaTypeClass = resolveParameterJavaType(parameterType, property, javaType, jdbcType);
    // 3、获取类型处理器,如果没配置类型处理器,那这里会返回null,但是后面build时会构造一个默认的类型处理器
    TypeHandler<?> typeHandlerInstance = resolveTypeHandler(javaTypeClass, typeHandler);
    // 4、构建ParameterMapping
    ParameterMapping.Builder builder = new ParameterMapping.Builder(configuration, property, javaTypeClass);
    builder.jdbcType(jdbcType);
    builder.resultMapId(resultMap);
    builder.mode(parameterMode);
    builder.numericScale(numericScale);
    builder.typeHandler(typeHandlerInstance);
    return builder.build();
  }

  /**
   * 将parameterMap存到configuration
   * @param id   parameterMap 的 ID
   * @param parameterClass  parameterMap对应的clazz,这个clazz可能是个对象类,也可能是个容器类
   * @param parameterMappings  parameterMap 的所有 parameter
   */
  public void addParameterMap(String id, Class<?> parameterClass, List<ParameterMapping> parameterMappings) {
    id = applyCurrentNamespace(id, false);
    ParameterMap.Builder parameterMapBuilder = new ParameterMap.Builder(id, parameterClass, parameterMappings);
    ParameterMap parameterMap = parameterMapBuilder.build();
    configuration.addParameterMap(parameterMap);
  }


  /**
   * 增加ResultMap
   * @param id 当前ResultMap的唯一标识
   * @param type 当前ResultMap对应的java类型
   * @param extend 当前ResultMap继承的ResultMap
   * @param discriminator 当前ResultMap的辨别器
   * @param resultMappings 当前ResultMap下的所有结果映射
   * @param autoMapping 是否自动映射
   */
  public ResultMap addResultMap(String id, Class<?> type, String extend, Discriminator discriminator, List<ResultMapping> resultMappings, Boolean autoMapping) {
    // 1、给id 和 extend 加上命名空间前缀
    id = applyCurrentNamespace(id, false);
    extend = applyCurrentNamespace(extend, true);
    // 2、创建ResultMap建造者
    ResultMap.Builder resultMapBuilder = new ResultMap.Builder(configuration, id, type, resultMappings, autoMapping);
    // 3、验证extend是否存在
    if (extend != null) {
      // a、如果configuration中没有该父类ResultMap，抛出异常
      if (!configuration.hasResultMap(extend)) {
        throw new IncompleteElementException("Could not find a parent resultMap with id '" + extend + "'");
      }
      // b、从configuration中获取该父类ResultMap
      ResultMap resultMap = configuration.getResultMap(extend);
      // c、获得该ResultMap的所有ResultMapping
      List<ResultMapping> extendedResultMappings = new ArrayList<>(resultMap.getResultMappings());
      // d、把父类中子类已经存在的ResultMapping删掉
      extendedResultMappings.removeAll(resultMappings);
      // e、如果子类声明了构造函数resultMapping，则删除父类resultMap的构造函数resultMapping。
      boolean declaresConstructor = false;
      for (ResultMapping resultMapping : resultMappings) {
        if (resultMapping.getFlags().contains(ResultFlag.CONSTRUCTOR)) {
          declaresConstructor = true;
          break;
        }
      }
      if (declaresConstructor) {
        extendedResultMappings.removeIf(resultMapping -> resultMapping.getFlags().contains(ResultFlag.CONSTRUCTOR));
      }
      // f、将父类留下来的resultMapping都添加到resultMappings中
      resultMappings.addAll(extendedResultMappings);
    }
    // 4、配置鉴别器
    resultMapBuilder.discriminator(discriminator);
    // 5、执行build
    ResultMap resultMap = resultMapBuilder.build();
    // 6、注册到configuration
    configuration.addResultMap(resultMap);
    // 7、返回
    return resultMap;
  }

  /**
   * 创建辨别器
   *    <discriminator javaType="int" column="draft" jdbcType="" typeHandler="">
   *        <case value="1" resultMap="DraftPost"/>
   *        <case value="2" resultMap="Post"/>
   *    </discriminator>
   * @param resultType    当前resultMap的type类型
   * @param column  当前辨别器对应的列名
   * @param javaType    当前辨别器的列名对应的java类型
   * @param jdbcType  当前辨别器的列名对应的jdbcType类型
   * @param typeHandler 类型处理器
   * @param discriminatorMap   <value,resultMap>容器
   * @return 鉴别器
   */
  public Discriminator buildDiscriminator(Class<?> resultType, String column, Class<?> javaType, JdbcType jdbcType, Class<? extends TypeHandler<?>> typeHandler, Map<String, String> discriminatorMap) {
    // 1、生成ResultMapping
    ResultMapping resultMapping = buildResultMapping(resultType, null, column, javaType, jdbcType, null, null, null, null, typeHandler, new ArrayList<>(), null, null, false);
    // 2、给discriminatorMap里的resultMap加上命名空间前缀
    Map<String, String> namespaceDiscriminatorMap = new HashMap<>();
    for (Map.Entry<String, String> e : discriminatorMap.entrySet()) {
      String resultMap = e.getValue();
      resultMap = applyCurrentNamespace(resultMap, true);
      namespaceDiscriminatorMap.put(e.getKey(), resultMap);
    }
    // 3、生成discriminatorBuilder构建器
    Discriminator.Builder discriminatorBuilder = new Discriminator.Builder(configuration, resultMapping, namespaceDiscriminatorMap);
    // 4、构建Discriminator并返回
    return discriminatorBuilder.build();
  }

  /**
   * 构建映射语句,并将其添加到configuration
   * @param id sql语句的id标识
   * @param sqlSource sql源, 一般是DynamicSqlSource
   * @param statementType 语句类型,默认为prepared预处理语句
   * @param sqlCommandType  Sql类型
   * @param fetchSize 限制批量返回的结果行数
   * @param timeout  等待数据库返回请求结果的秒数,超时抛出异常
   * @param parameterMap 引用外部 parameterMap,已废弃
   * @param parameterType 参数类型
   * @param resultMap 结果映射ID
   * @param resultType 结果类型
   * @param resultSetType resultSet类型，默认为unset ,暂时不晓得这干嘛的
   * @param flushCache 是否清空缓存,如果是查询语句默认不清空,其他增删改则默认清空
   * @param useCache 是否缓存查询结果 ,默认为true
   * @param resultOrdered 只针对查询语句,加了这个自动分组。具体还得以后再看
   * @param keyGenerator 键值生成器,分两种情况。
   * @param keyProperty 标记一个属性(通常就是标记id),MyBatis会通过getGeneratedKeys或者通过insert语句的selectKey子元素设置它的值
   * @param keyColumn  标记一个属性(通常就是标记id),MyBatis会通过getGeneratedKeys或者通过insert语句的selectKey子元素设置它的值
   * @param databaseId 数据库ID
   * @param lang 语言驱动,默认为 XMLLanguageDriver
   * @param resultSets 多结果集
   * @return  MappedStatement
   */
  public MappedStatement addMappedStatement(
      String id,
      SqlSource sqlSource,
      StatementType statementType,
      SqlCommandType sqlCommandType,
      Integer fetchSize,
      Integer timeout,
      String parameterMap,
      Class<?> parameterType,
      String resultMap,
      Class<?> resultType,
      ResultSetType resultSetType,
      boolean flushCache,
      boolean useCache,
      boolean resultOrdered,
      KeyGenerator keyGenerator,
      String keyProperty,
      String keyColumn,
      String databaseId,
      LanguageDriver lang,
      String resultSets) {

    // 1、确保引进缓存对象
    if (unresolvedCacheRef) {
      throw new IncompleteElementException("Cache-ref not yet resolved");
    }

    // 2、为id加上namespace前缀
    id = applyCurrentNamespace(id, false);

    // 3、建造者模式
    MappedStatement.Builder statementBuilder = new MappedStatement.Builder(configuration, id, sqlSource, sqlCommandType);
    statementBuilder.resource(resource);
    statementBuilder.fetchSize(fetchSize);
    statementBuilder.statementType(statementType);
    statementBuilder.keyGenerator(keyGenerator);
    statementBuilder.keyProperty(keyProperty);
    statementBuilder.keyColumn(keyColumn);
    statementBuilder.databaseId(databaseId);
    statementBuilder.lang(lang);
    statementBuilder.resultOrdered(resultOrdered);
    statementBuilder.resulSets(resultSets);
    // a、设置超时时间,如果用户没设置就取configuration中的
    setStatementTimeout(timeout, statementBuilder);
    // b、参数映射
    setStatementParameterMap(parameterMap, parameterType, statementBuilder);
    // c、结果映射
    setStatementResultMap(resultMap, resultType, resultSetType, statementBuilder);
    // d、缓存
    setStatementCache(sqlCommandType == SqlCommandType.SELECT, flushCache, useCache, currentCache, statementBuilder);

    MappedStatement statement = statementBuilder.build();
    // e、建造好调用configuration.addMappedStatement
    configuration.addMappedStatement(statement);
    return statement;
  }


  /**
   * 设置sql语句的超时时间
   * @param timeout
   * @param statementBuilder
   */
  private void setStatementTimeout(Integer timeout, MappedStatement.Builder statementBuilder) {
    if (timeout == null) {
      timeout = configuration.getDefaultStatementTimeout();
    }
    statementBuilder.timeout(timeout);
  }

  /**
   * 设置sql语句的参数映射
   * @param parameterMap sql节点中配置的parameterMap属性
   * @param parameterTypeClass sql节点中配置的parameterType类
   * @param statementBuilder   sql语句
   */
  private void setStatementParameterMap(String parameterMap, Class<?> parameterTypeClass, MappedStatement.Builder statementBuilder) {
    parameterMap = applyCurrentNamespace(parameterMap, true);
    // 1、如果parameterMap不为null ,那直接从configuration里取出
    if (parameterMap != null) {
      try {
        statementBuilder.parameterMap(configuration.getParameterMap(parameterMap));
      } catch (IllegalArgumentException e) {
        throw new IncompleteElementException("Could not find parameter map " + parameterMap, e);
      }
    } else if (parameterTypeClass != null) {
      // 2、如果parameterMap为null,则根据parameterTypeClass生成ParameterMap
      List<ParameterMapping> parameterMappings = new ArrayList<>();
      ParameterMap.Builder inlineParameterMapBuilder = new ParameterMap.Builder(statementBuilder.id() + "-Inline", parameterTypeClass, parameterMappings);
      statementBuilder.parameterMap(inlineParameterMapBuilder.build());
    }
  }

  /**
   * 给sql语句配置结果映射
   * @param resultMap 结果映射集id
   * @param resultType 结果映射类型
   * @param resultSetType resultSet类型，默认为unset
   * @param statementBuilder sql语句
   */
  private void setStatementResultMap(String resultMap, Class<?> resultType, ResultSetType resultSetType, MappedStatement.Builder statementBuilder) {
    resultMap = applyCurrentNamespace(resultMap, true);
    List<ResultMap> resultMaps = new ArrayList<>();
    if (resultMap != null) {
      //2.1 resultMap,这里搞了个split不知道干嘛的(意思是可以搞多个resultMap？)
      String[] resultMapNames = resultMap.split(",");
      for (String resultMapName : resultMapNames) {
        try {
          resultMaps.add(configuration.getResultMap(resultMapName.trim()));
        } catch (IllegalArgumentException e) {
          throw new IncompleteElementException("Could not find result map " + resultMapName, e);
        }
      }
    } else if (resultType != null) {
      //2.2 如果resultMap为null,创建默认的ResultMap,就看resultType,基于属性名来映射列到JavaBean的属性,如果没有精确匹配,可以使用select字句的别名来匹配标签
      ResultMap.Builder inlineResultMapBuilder = new ResultMap.Builder(configuration, statementBuilder.id() + "-Inline", resultType, new ArrayList<>(), null);
      resultMaps.add(inlineResultMapBuilder.build());
    }
    statementBuilder.resultMaps(resultMaps);
    statementBuilder.resultSetType(resultSetType);
  }

  /**
   * 给sql语句配置缓存
   * @param isSelect   是否为select语句
   * @param flushCache 是否清空一二级缓存，增删改默认为true
   * @param useCache 是否要缓存结果,select 默认为true
   * @param cache 表示当前xml的缓存
   * @param statementBuilder sql语句
   */
  private void setStatementCache(boolean isSelect, boolean flushCache, boolean useCache, Cache cache, MappedStatement.Builder statementBuilder) {
    flushCache = valueOrDefault(flushCache, !isSelect);
    useCache = valueOrDefault(useCache, isSelect);
    statementBuilder.flushCacheRequired(flushCache);
    statementBuilder.useCache(useCache);
    statementBuilder.cache(cache);
  }

  /**
   * 构建ResultMapping
   * @param resultType  当前resultMap的type类型
   * @param property JavaBean中的属性名
   * @param column 数据库中的列名
   * @param javaType ..如果是个集合？
   * @param jdbcType ..
   * @param nestedSelect 内嵌的查询语句
   * @param nestedResultMap 内嵌的结果映射
   * @param notNullColumn .. 某个属性不为null 才构建子对象
   * @param columnPrefix .. 映射同名属性的情况下,用这个作为前缀
   * @param typeHandler .. 类型处理器
   * @param flags ..  结果标志集合  ？？？
   * @param resultSet ..  多结果集设置
   * @param foreignColumn ..多结果集下，两个结果集之间的关联键
   * @param lazy ..  是否支持懒加载
   */
  public ResultMapping buildResultMapping(
      Class<?> resultType,
      String property,
      String column,
      Class<?> javaType,
      JdbcType jdbcType,
      String nestedSelect,
      String nestedResultMap,
      String notNullColumn,
      String columnPrefix,
      Class<? extends TypeHandler<?>> typeHandler,
      List<ResultFlag> flags,
      String resultSet,
      String foreignColumn,
      boolean lazy) {
    // 1、解析属性类型,默认为Object.class
    Class<?> javaTypeClass = resolveResultJavaType(resultType, property, javaType);
    // 2、获取类型处理器
    TypeHandler<?> typeHandlerInstance = resolveTypeHandler(javaTypeClass, typeHandler);
    // 3、解析复合列名,类似 column="{prop1=col1,prop2=col2}"
    List<ResultMapping> composites = parseCompositeColumnName(column);
    if (composites.size() > 0) {
      // 如果是复合列名,则column设置为null
      column = null;
    }
    // 4、构建ResultMapping
    ResultMapping.Builder builder = new ResultMapping.Builder(configuration, property, column, javaTypeClass);
    builder.jdbcType(jdbcType);
    builder.nestedQueryId(applyCurrentNamespace(nestedSelect, true));
    builder.nestedResultMapId(applyCurrentNamespace(nestedResultMap, true));
    builder.resultSet(resultSet);
    builder.typeHandler(typeHandlerInstance);
    builder.flags(flags == null ? new ArrayList<>() : flags);
    builder.composites(composites);
    builder.notNullColumns(parseMultipleColumnNames(notNullColumn));
    builder.columnPrefix(columnPrefix);
    builder.foreignColumn(foreignColumn);
    builder.lazy(lazy);
    return builder.build();
  }

  /**
   * 解析复合列名，即列名由多个组成
   * 在使用复合主键的时候，可以使用 column="{prop1=col1,prop2=col2}" 这样的语法来指定多个传递给嵌套 Select 查询语句的列名
   * @param columnName {prop1=col1,prop2=col2}
   */
  private List<ResultMapping> parseCompositeColumnName(String columnName) {
    // 1、创建ResultMapping集合
    List<ResultMapping> composites = new ArrayList<>();
    // 2、判断columnName存在且存在"="或","
    if (columnName != null && (columnName.indexOf('=') > -1 || columnName.indexOf(',') > -1)) {
      // a、创建字符串标记器类，以"{}=,"为分隔符,解析columnName
      StringTokenizer parser = new StringTokenizer(columnName, "{}=, ", false);
      // b、使用死循环,一次读两个,正好对应属性名和列名
      while (parser.hasMoreTokens()) {
        String property = parser.nextToken();
        String column = parser.nextToken();
        // c、构建ResultMapping并添加进composites
        ResultMapping.Builder complexBuilder = new ResultMapping.Builder(configuration, property, column, configuration.getTypeHandlerRegistry().getUnknownTypeHandler());
        composites.add(complexBuilder.build());
      }
    }
    // 3、返回ResultMapping集合
    return composites;
  }

  /**
   * 解析复合列名，即列名由多个组成
   * @param columnName {prop1,prop2}
   */
  private Set<String> parseMultipleColumnNames(String columnName) {
    Set<String> columns = new HashSet<>();
    if (columnName != null) {
      if (columnName.indexOf(',') > -1) {
        StringTokenizer parser = new StringTokenizer(columnName, "{}, ", false);
        while (parser.hasMoreTokens()) {
          String column = parser.nextToken();
          columns.add(column);
        }
      } else {
        columns.add(columnName);
      }
    }
    return columns;
  }

  /**
   * 找到属性对应的类型,找不到就为Object.class
   * @param resultType  目标类
   * @param property   某属性
   * @param javaType   该属性对应的类型
   */
  private Class<?> resolveResultJavaType(Class<?> resultType, String property, Class<?> javaType) {
    // 1、如果该属性类型为null ,但存在属性名，就借助元对象去找属性类型
    if (javaType == null && property != null) {
      try {
        MetaClass metaResultType = MetaClass.forClass(resultType);
        javaType = metaResultType.getSetterType(property);
      } catch (Exception ignored) {
      }
    }
    // 2、如果该属性类型为null ,且其元对象中也没找到该属性类型，则设置为Object.class
    if (javaType == null) {
      javaType = Object.class;
    }
    // 3、返回
    return javaType;
  }

  /**
   * 解析参数类型
   * @param resultType  属性所在类 || 元素所在容器
   * @param property 属性名
   * @param javaType 属性类型
   * @param jdbcType 属性对应的jdbc类型
   * @return
   */
  private Class<?> resolveParameterJavaType(Class<?> resultType, String property, Class<?> javaType, JdbcType jdbcType) {
    if (javaType == null) {
      if (JdbcType.CURSOR.equals(jdbcType)) {
        // 1、假如jdbcType是CURSOR,则javaType置为ResultSet类型
        javaType = java.sql.ResultSet.class;
      } else if (Map.class.isAssignableFrom(resultType)) {
        // 2、如果resultType是Map类型,这种定位不了具体类型，则javaType置为Object类型,
        javaType = Object.class;
      } else {
        // 3、假如jdbcType不是CURSOR、且resultType不是Map类型,则尝试利用MetaClass来根据属性名获取类型
        MetaClass metaResultType = MetaClass.forClass(resultType);
        javaType = metaResultType.getGetterType(property);
      }
    }
    if (javaType == null) {
      // 4、假如用户傻逼了,把属性名写错了,则javaType置为Object类型
      javaType = Object.class;
    }
    return javaType;
  }

  /** Backward compatibility signature */
  //向后兼容方法
  public ResultMapping buildResultMapping(
      Class<?> resultType,
      String property,
      String column,
      Class<?> javaType,
      JdbcType jdbcType,
      String nestedSelect,
      String nestedResultMap,
      String notNullColumn,
      String columnPrefix,
      Class<? extends TypeHandler<?>> typeHandler,
      List<ResultFlag> flags) {
      return buildResultMapping(
        resultType, property, column, javaType, jdbcType, nestedSelect,
        nestedResultMap, notNullColumn, columnPrefix, typeHandler, flags, null, null, configuration.isLazyLoadingEnabled());
  }

  /**
   * 取得语言驱动
   * @param langClass 驱动类
   * @return LanguageDriver
   */
  public LanguageDriver getLanguageDriver(Class<?> langClass) {
    if (langClass != null) {
      //1、注册语言驱动
      configuration.getLanguageRegistry().register(langClass);
    } else {
      //2、如果为null，则取得默认驱动（mybatis3.2以前大家一直用的方法）
      langClass = configuration.getLanguageRegistry().getDefaultDriverClass();
    }
    // 2、再去调configuration
    return configuration.getLanguageRegistry().getDriver(langClass);
  }

  /** Backward compatibility signature */
  //向后兼容方法
  public MappedStatement addMappedStatement(
    String id,
    SqlSource sqlSource,
    StatementType statementType,
    SqlCommandType sqlCommandType,
    Integer fetchSize,
    Integer timeout,
    String parameterMap,
    Class<?> parameterType,
    String resultMap,
    Class<?> resultType,
    ResultSetType resultSetType,
    boolean flushCache,
    boolean useCache,
    boolean resultOrdered,
    KeyGenerator keyGenerator,
    String keyProperty,
    String keyColumn,
    String databaseId,
    LanguageDriver lang) {
    return addMappedStatement(
      id, sqlSource, statementType, sqlCommandType, fetchSize, timeout,
      parameterMap, parameterType, resultMap, resultType, resultSetType,
      flushCache, useCache, resultOrdered, keyGenerator, keyProperty,
      keyColumn, databaseId, lang, null);
  }


  private <T> T valueOrDefault(T value, T defaultValue) {
    return value == null ? defaultValue : value;
  }

}
