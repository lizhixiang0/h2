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
package org.apache.ibatis.builder.xml;

import java.io.InputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.ibatis.builder.BaseBuilder;
import org.apache.ibatis.builder.BuilderException;
import org.apache.ibatis.builder.CacheRefResolver;
import org.apache.ibatis.builder.IncompleteElementException;
import org.apache.ibatis.builder.MapperBuilderAssistant;
import org.apache.ibatis.builder.ResultMapResolver;
import org.apache.ibatis.cache.Cache;
import org.apache.ibatis.executor.ErrorContext;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.mapping.Discriminator;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.mapping.ParameterMode;
import org.apache.ibatis.mapping.ResultFlag;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.mapping.ResultMapping;
import org.apache.ibatis.parsing.XNode;
import org.apache.ibatis.parsing.XPathParser;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeHandler;

/**
 * XML映射解析器,一个mapper.xml对应一个
 * @author Clinton Begin
 */
public class XMLMapperBuilder extends BaseBuilder {

  private XPathParser parser;
  //映射器构建助手
  private MapperBuilderAssistant builderAssistant;
  private Map<String, XNode> sqlFragments;
  private String resource;

  @Deprecated
  public XMLMapperBuilder(Reader reader, Configuration configuration, String resource, Map<String, XNode> sqlFragments, String namespace) {
    this(reader, configuration, resource, sqlFragments);
    this.builderAssistant.setCurrentNamespace(namespace);
  }

  @Deprecated
  public XMLMapperBuilder(Reader reader, Configuration configuration, String resource, Map<String, XNode> sqlFragments) {
    this(new XPathParser(reader, true, configuration.getVariables(), new XMLMapperEntityResolver()),
        configuration, resource, sqlFragments);
  }

  public XMLMapperBuilder(InputStream inputStream, Configuration configuration, String resource, Map<String, XNode> sqlFragments, String namespace) {
    this(inputStream, configuration, resource, sqlFragments);
    this.builderAssistant.setCurrentNamespace(namespace);
  }

  public XMLMapperBuilder(InputStream inputStream, Configuration configuration, String resource, Map<String, XNode> sqlFragments) {
    this(new XPathParser(inputStream, true, configuration.getVariables(), new XMLMapperEntityResolver()),
        configuration, resource, sqlFragments);
  }

  /**
   * 核心方法,其他方法都是对本方法的重载
   * @param parser  mybatis自己使用的XPath解析器,用来解读mapper.xml文件
   * @param configuration 核心配置类
   * @param resource  映射文件的绝对或相对路径
   * @param sqlFragments 存放sql片段的哈希表
   */
  private XMLMapperBuilder(XPathParser parser, Configuration configuration, String resource, Map<String, XNode> sqlFragments) {
    super(configuration);
    // 生成构造助手
    this.builderAssistant = new MapperBuilderAssistant(configuration, resource);
    this.parser = parser;
    this.sqlFragments = sqlFragments;
    this.resource = resource;
  }

  /**
   *  XMLConfigBuilder类里配置文件都解读完后,调用这个方法解析映射文件
   */
  public void parse() {
    // 1、判断该xml有没有解析过
    if (!configuration.isResourceLoaded(resource)) {
      // 1.1 没有解析过,开始解析
      configurationElement(parser.evalNode("/mapper"));
      // 1.2 解析完记录下，下次就不解析了
      configuration.addLoadedResource(resource);
      // 1.3、绑定映射器到namespace
      bindMapperForNamespace();
    }

    //还有没解析完的东东这里接着解析？
    parsePendingResultMaps();
    parsePendingChacheRefs();
    parsePendingStatements();
  }

  public XNode getSqlFragment(String refid) {
    return sqlFragments.get(refid);
  }

  /**
   * 解析mapper节点
   *
   * 	<mapper namespace="org.mybatis.example.BlogMapper">
   *
   * 	  <parameterMap id="ParameterMap" type="Student">
   *          <parameter property="studentId" resultMap="ResultMap"/>
   *          <parameter property="studentName" resultMap="ResultMap"/>
   *          <parameter property="studentAge" resultMap="ResultMap"/>
   *      </parameterMap>
   *
   *      <resultMap id="ResultMap" type="Student">
   *          <id column="id" property="studentId"></id>
   *          <result column="name" property="studentName"></result>
   *          <result column="age" property="studentAge"></result>
   *      </resultMap>
   *
   * 	  <cache-ref namespace="com.x.x.x.XXXMapper"/>
   *
   *      <cache eviction="FIFO" flushInterval="6000" size="512" readOnly="false"/>
   *
   * 	  <select id="selectBlog" parameterType="int" resultType="Blog">
   * 	    select * from Blog where id = #{id}
   * 	  </select>
   *
   * 	</mapper>
   * @param context 表示mapper节点
   */
  private void configurationElement(XNode context) {
    try {
      //1.配置namespace
      String namespace = context.getStringAttribute("namespace");
      if ("".equals(namespace)) {
        throw new BuilderException("Mapper's namespace cannot be empty");
      }
      builderAssistant.setCurrentNamespace(namespace);
      //2.配置cache-ref
      cacheRefElement(context.evalNode("cache-ref"));
      //3.配置cache
      cacheElement(context.evalNode("cache"));
      //4.配置parameterMap
      parameterMapElement(context.evalNodes("/mapper/parameterMap"));
      //5.配置resultMap(高级功能)
      resultMapElements(context.evalNodes("/mapper/resultMap"));
      //6.配置sql(定义可重用的 SQL 代码段)
      sqlElement(context.evalNodes("/mapper/sql"));
      //7.配置select|insert|update|delete TODO
      buildStatementFromContext(context.evalNodes("select|insert|update|delete"));
    } catch (Exception e) {
      throw new BuilderException("Error parsing Mapper XML. Cause: " + e, e);
    }
  }

  /**
   * 1、为当前命名空间引用其他命名空间的缓存
   * <cache-ref namespace="com.someone.application.data.SomeMapper"/>
   * @param context cache-ref节点
   */
  private void cacheRefElement(XNode context) {
    if (context != null) {
      // 1、把引用关系存储到configuration
      configuration.addCacheRef(builderAssistant.getCurrentNamespace(), context.getStringAttribute("namespace"));
      // 2、生成缓存引用解析器
      CacheRefResolver cacheRefResolver = new CacheRefResolver(builderAssistant, context.getStringAttribute("namespace"));
      try {
        // 3、开始解析,其实就是把引用过来的缓存赋值给了当前缓存
        cacheRefResolver.resolveCacheRef();
      } catch (IncompleteElementException e) {
        configuration.addIncompleteCacheRef(cacheRefResolver);
      }
    }
  }

  /**
   * 2、为当前命名空间配置缓存
   * <cache type="com.domain.something.MyCustomCache" eviction="FIFO" flushInterval="6000" size="512" readOnly="false">
   *    <property name="cacheFile" value="/tmp/my-custom-cache.tmp"/>
   * </cache>
   * @param context cache节点
   */
  private void cacheElement(XNode context) {
    if (context != null) {
      // 1、获取缓存类型,没有就返回PERPETUAL
      String type = context.getStringAttribute("type", "PERPETUAL");
      // 根据type从别名注册表中获得具体的cache clazz  （所以这玩意儿可以自己实现,然后注册到别名注册表中）
      Class<? extends Cache> typeClass = typeAliasRegistry.resolveAlias(type);
      // 2、获取淘汰策略,默认使用最少使用缓存淘汰算法 （LRU）
      String eviction = context.getStringAttribute("eviction", "LRU");
      Class<? extends Cache> evictionClass = typeAliasRegistry.resolveAlias(eviction);
      // 3、获取冲刷间隔
      Long flushInterval = context.getLongAttribute("flushInterval");
      // 4、获取缓存大小
      Integer size = context.getIntAttribute("size");
      // 5、获得读写权限 （默认为可读写）
      boolean readWrite = !context.getBooleanAttribute("readOnly", false);
      // 6、获得阻塞设置 （默认为false不使用）
      boolean blocking = context.getBooleanAttribute("blocking", false);
      // 7、获得子节点的属性名及属性
      Properties props = context.getChildrenAsProperties();
      // 8、使用助手创建缓存
      builderAssistant.useNewCache(typeClass, evictionClass, flushInterval, size, readWrite, blocking, props);
    }
  }

  /**
   * 3.解析所有parameterMap节点  (开发中比较少见)
   *   它可以用于指定实体类字段属性与数据库字段属性的映射关系，
   *   这样一来当传入参数实体类中的字段名和数据库的字段名名称上没有对应也能查询出想要的结果，这就是parameterMap的作用。
   *   并且可以和resultMap搭配使用。
   *   <parameterMap id="ParameterMap" type="Student">
   *         <parameter property="studentId" resultMap="ResultMap"/>
   *         <parameter property="studentName" resultMap="ResultMap"/>
   *         <parameter property="studentAge" resultMap="ResultMap"/>
   *   </parameterMap>
   *
   *   <parameterMap  id="getInstProgressIdParaMap" type="java.util.HashMap">
   *     <parameter property="p_callFlag" javaType="java.lang.String" jdbcType="VARCHAR" mode="IN"/>
   *     <parameter property="P_accNbr" javaType="java.lang.String" jdbcType="VARCHAR" mode="IN"/>
   *     <parameter property="P_Type" javaType="java.lang.String" jdbcType="VARCHAR" mode="IN"/>
   *     <parameter property="P_areaId" javaType="java.lang.String" jdbcType="VARCHAR" mode="IN"/>
   *     <parameter property="P_Id" javaType="java.lang.Integer" jdbcType="INTEGER" mode="OUT"/>
   * </parameterMap>
   * @param list  parameterMap节点  这个节点可能会出现多个,所以用list
   */
  private void parameterMapElement(List<XNode> list) {
    // 1、遍历处理所有<parameterMap>
    for (XNode parameterMapNode : list) {
      String id = parameterMapNode.getStringAttribute("id");
      String type = parameterMapNode.getStringAttribute("type");
      Class<?> parameterClass = resolveClass(type);
      // 获取parameterMap节点下所有的parameter节点
      List<XNode> parameterNodes = parameterMapNode.evalNodes("parameter");
      // 创建参数映射集合
      List<ParameterMapping> parameterMappings = new ArrayList<>();
      // 2、遍历处理所有<parameter>,每一个<parameter>都能生成一个ParameterMapping
      for (XNode parameterNode : parameterNodes) {
        // a、对象中该属性名
        String property = parameterNode.getStringAttribute("property");
        // b、该属性的java类型
        String javaType = parameterNode.getStringAttribute("javaType");
        // c、该属性的jdbc类型
        String jdbcType = parameterNode.getStringAttribute("jdbcType");
        // d、该属性对应的resultMap ID
        String resultMap = parameterNode.getStringAttribute("resultMap");
        // e、该属性的参数模式
        String mode = parameterNode.getStringAttribute("mode");
        // f、该属性的类型处理器
        String typeHandler = parameterNode.getStringAttribute("typeHandler");
        // g、该属性保留小数点后几位
        Integer numericScale = parameterNode.getIntAttribute("numericScale");

        ParameterMode modeEnum = super.resolveParameterMode(mode);
        Class<?> javaTypeClass = super.resolveClass(javaType);
        JdbcType jdbcTypeEnum = super.resolveJdbcType(jdbcType);
        @SuppressWarnings("unchecked")
        Class<? extends TypeHandler<?>> typeHandlerClass = (Class<? extends TypeHandler<?>>) resolveClass(typeHandler);
        // h、构建ParameterMapping
        ParameterMapping parameterMapping = builderAssistant.buildParameterMapping(parameterClass, property, javaTypeClass, jdbcTypeEnum, resultMap, modeEnum, typeHandlerClass, numericScale);
        // i、将parameterMapping添加进参数映射集合
        parameterMappings.add(parameterMapping);
      }
      // 3、借助助理将该parameterMap存到configuration
      builderAssistant.addParameterMap(id, parameterClass, parameterMappings);
    }
  }

  /**
   *  4、解析所有resultMap节点 ,将查询的结果映射到具体的对象中
   *
   *      <resultMap id="peopleResultMap" type="org.sang.bean.User">
   *         <id property="id" column="id"/>
   *         <result property="id" column="id"/>
   *      </resultMap>
   *
   *      <resultMap id="userResultMap" type="org.sang.bean.User" extends = "peopleResultMap">
   *
   *         <id property="id" column="id"/>
   *         <result property="id" column="id" javaType="" jdbcType="" typeHandler=""/>
   *
   *         < a、constructor主要是用来配置构造方法，默认情况下mybatis会调用实体类的无参构造方法创建一个实体类,然后再给各个属性赋值>
   *         <constructor>
   *             <idArg column="" javaType="" jdbcType="" />
   *             <arg name="" column="" javaType="" jdbcType=""  typeHandler="" resultMap="" select=""/>
   *         </constructor>
   *
   *         < b、association是mybatis支持级联的一部分,主要是用来解决一对一关系的，可以配置延迟加载>
   *         <association property=""  column=""  select="" fetchType="eager"/>
   *
   *         < c、collection是用来解决一对多级联的,可以配置延迟加载>
   *         <collection property="" column=""  select="" fetchType="eager"/>
   *
   *         < d、鉴别器级联、使用它我们可以在不同的条件下执行不同的查询为该属性匹配不同的实体类
   *         <discriminator javaType="" column="">
   *             <case value="" resultMap="1"></case>
   *             <case value="" resultMap="2"></case>
   *         </discriminator>
   *
   *     </resultMap>
   *
   *     <resultMap id="1" type="" extends="">
   *         <collection property="" column="area" select=""/>
   *     </resultMap>
   *
   *     <resultMap id="2" type="" extends="">
   *         <collection property="" column="area" select=""/>
   *     </resultMap>
   *
   *     resultMap中一共有六种不同的节点
   *
   * @param list resultMap节点 ,会出现多个,所以用list
   * @link "https://blog.csdn.net/u012702547/article/details/54599132
   * @link 官网介绍: https://mybatis.org/mybatis-3/zh/sqlmap-xml.html#Result_Maps
   */
  private void resultMapElements(List<XNode> list) throws Exception {
    // 循环遍历list
    for (XNode resultMapNode : list) {
      try {
        resultMapElement(resultMapNode);
      } catch (IncompleteElementException ignored) {
      }
    }
  }

  /**
   * 4.1 解析resultMap节点
   * @param resultMapNode 单个resultMap节点
   */
  private void resultMapElement(XNode resultMapNode) throws Exception {
    resultMapElement(resultMapNode, Collections.emptyList());
  }

  /**
   * 4.2 解析resultMap节点
   * @param resultMapNode 单个resultMap节点
   * @param additionalResultMappings  额外提供的空集合容器,不知道干啥玩意
   */
  private ResultMap resultMapElement(XNode resultMapNode, List<ResultMapping> additionalResultMappings) throws Exception {
    // 1、定义全局异常跟踪
    ErrorContext.instance().activity("processing " + resultMapNode.getValueBasedIdentifier());
    // 2、取得当前resultMap的ID标识(标识结果映射),没有就用全路径标识符
    String id = resultMapNode.getStringAttribute("id",resultMapNode.getValueBasedIdentifier());
    // 3、取得类的全限定名或其类型别名,没配置为null    (兼容老代码,type == ofType == resultType == javaType)
    String type = resultMapNode.getStringAttribute("type",resultMapNode.getStringAttribute("ofType",resultMapNode.getStringAttribute("resultType",resultMapNode.getStringAttribute("javaType"))));
    // 4、取得继承的ResultMap ID,没配置为null
    String extend = resultMapNode.getStringAttribute("extends");
    // 5、取得autoMapping,没配置为null,如果设置这个属性，MyBatis 将会为本结果映射开启或者关闭自动映射
    Boolean autoMapping = resultMapNode.getBooleanAttribute("autoMapping");
    Class<?> typeClass = resolveClass(type);
    Discriminator discriminator = null;
    // 6、创建结果映射集合
    List<ResultMapping> resultMappings = new ArrayList<>(additionalResultMappings);
    // 7、获得当前resultMap节点的所有子节点
    List<XNode> resultChildren = resultMapNode.getChildren();
    // 8、遍历子节点
    for (XNode resultChild : resultChildren) {
      if ("constructor".equals(resultChild.getName())) {
        // a、如果是constructor节点
        processConstructorElement(resultChild, typeClass, resultMappings);
      } else if ("discriminator".equals(resultChild.getName())) {
        // b、如果是discriminator节点
        discriminator = processDiscriminatorElement(resultChild, typeClass, resultMappings);
      } else {
        // c、既不是构造器节点,也不是鉴别器，创建结果标志集合
        List<ResultFlag> flags = new ArrayList<>();
        if ("id".equals(resultChild.getName())) {
          // c1、如果是ID节点，则结果标志集合 + ID
          flags.add(ResultFlag.ID);
        }
        //c2、构建ResultMapping并放入集合
        resultMappings.add(buildResultMappingFromContext(resultChild, typeClass, flags));
      }
    }
    // 9、构建ResultMapResolver
    ResultMapResolver resultMapResolver = new ResultMapResolver(builderAssistant, id, typeClass, extend, discriminator, resultMappings, autoMapping);
    try {
      // 10、解析,返回ResultMap
      return resultMapResolver.resolve();
    } catch (IncompleteElementException  e) {
      configuration.addIncompleteResultMap(resultMapResolver);
      throw e;
    }
  }

  /**
   * 4.3.1、解析resultMap的constructor
   *
   * e.q.
   *        public class User {
   *            //...
   *            public User(Integer id, String username, int age) {
   *            //...
   *            }
   *        }
   *
   *        <constructor>
   *          <idArg column="id" javaType="int" name="id" />
   *          <arg column="age" javaType="_int" name="age" />
   *          <arg column="username" javaType="String" name="username" />
   *        </constructor>

   * @param resultChild 当前constructor节点
   * @param resultType  当前resultMap的type类型
   * @param resultMappings  结果映射集合
   */
  private void processConstructorElement(XNode resultChild, Class<?> resultType, List<ResultMapping> resultMappings) throws Exception {
    // 1、获取所有子节点
    List<XNode> argChildren = resultChild.getChildren();
    // 2、遍历所有子节点
    for (XNode argChild : argChildren) {
      // a、创建结果标志集合
      List<ResultFlag> flags = new ArrayList<>();
      // b、结果标志集合 +CONSTRUCTOR
      flags.add(ResultFlag.CONSTRUCTOR);
      if ("idArg".equals(argChild.getName())) {
        // c、如果是idArg子节点,则结果标志集合 + ID
        flags.add(ResultFlag.ID);
      }
      // d、构建resultMapping并将其存放到resultMappings集合中
      resultMappings.add(buildResultMappingFromContext(argChild, resultType, flags));
    }
  }


  /**
   * 4.3.2、解析resultMap的Discriminator节点
   * <discriminator javaType="int" column="draft">
   *   <case value="1" resultType="DraftPost"/>
   * </discriminator>
   * @param context 当前discriminator节点
   * @param resultType 当前resultMap的type类型
   * @param resultMappings 结果映射集合
   */
  private Discriminator processDiscriminatorElement(XNode context, Class<?> resultType, List<ResultMapping> resultMappings) throws Exception {
    String column = context.getStringAttribute("column");
    String javaType = context.getStringAttribute("javaType");
    String jdbcType = context.getStringAttribute("jdbcType");
    String typeHandler = context.getStringAttribute("typeHandler");
    Class<?> javaTypeClass = resolveClass(javaType);
    @SuppressWarnings("unchecked")
    Class<? extends TypeHandler<?>> typeHandlerClass = (Class<? extends TypeHandler<?>>) resolveClass(typeHandler);
    JdbcType jdbcTypeEnum = resolveJdbcType(jdbcType);
    Map<String, String> discriminatorMap = new HashMap<>();
    for (XNode caseChild : context.getChildren()) {
      String value = caseChild.getStringAttribute("value");
      String resultMap = caseChild.getStringAttribute("resultMap", processNestedResultMappings(caseChild, resultMappings));
      discriminatorMap.put(value, resultMap);
    }
    return builderAssistant.buildDiscriminator(resultType, column, javaTypeClass, jdbcTypeEnum, typeHandlerClass, discriminatorMap);
  }


  /**
   * 4.4 从当前节点体内取的配置的信息,构建resultMap
   *
   * @param context  当前节点,其父节点可能是resultMap节点也可能是constructor节点
   * @param resultType  当前resultMap的type类型
   * @param flags 结果标志集合  ？？？
   * @link  "https://mybatis.org/mybatis-3/zh/sqlmap-xml.html#Result_Maps
   */
  private ResultMapping buildResultMappingFromContext(XNode context, Class<?> resultType, List<ResultFlag> flags) throws Exception {
    // 1、取property, JavaBean中的属性名,可以是简单的name,也可以用常见的点式分隔形式进行复杂属性导航,如user.name
    String property = context.getStringAttribute("property");
    // 2、取column, 数据库中的列名，或者是列的别名
    String column = context.getStringAttribute("column");
    // 3、取javaType, 类的全限定名或类型别名,用来表示该属性的java类型，
    String javaType = context.getStringAttribute("javaType");
    // 4、取jdbcType, JDBC类型
    String jdbcType = context.getStringAttribute("jdbcType");
    // 5、取select,内嵌的查询语句,从column属性指定的列检索数据,作为参数传递给此 select 语句,不推荐使用。
    String nestedSelect = context.getStringAttribute("select");
    // 6、取resultMap,将嵌套的结果集映射到一个合适的对象树中,作为使用额外 select 语句的替代方案
    String nestedResultMap = context.getStringAttribute("resultMap",processNestedResultMappings(context, Collections.emptyList()));
    // 7、取notNullColumn,默认是只要有一个属性不为空就创建子对象,可以指定只有当某个属性不为空才创建子对象
    String notNullColumn = context.getStringAttribute("notNullColumn");
    // 8、取columnPrefix,连接多个表时,避免在ResultSet中产生重复的列名,通常我们会给加以前缀来区分,然后做结果映射时就能用到这个
    String columnPrefix = context.getStringAttribute("columnPrefix");
    // 9、取typeHandler,类型处理器类的全限定名(或类型别名),可以覆盖默认的类型处理器
    String typeHandler = context.getStringAttribute("typeHandler");
    // 10、取resultSet,如果存在多个结果集,先在映射语句中通过resultSets属性为每个结果集指定一个名字,然后在关联节点里指定对应的结果集
    String resultSet = context.getStringAttribute("resultSet");
    // 11、取foreignColumn,指定对应的外键列名,如果当前节点有这个属性,则column表示结果集中用于与外键匹配的列
    String foreignColumn = context.getStringAttribute("foreignColumn");
    // 12、取fetchType,懒加载
    boolean lazy = "lazy".equals(context.getStringAttribute("fetchType", configuration.isLazyLoadingEnabled() ? "lazy" : "eager"));
    Class<?> javaTypeClass = resolveClass(javaType);
    @SuppressWarnings("unchecked")
    Class<? extends TypeHandler<?>> typeHandlerClass = (Class<? extends TypeHandler<?>>) resolveClass(typeHandler);
    JdbcType jdbcTypeEnum = resolveJdbcType(jdbcType);
    // 13、使用builderAssistant生成ResultMapping
    return builderAssistant.buildResultMapping(resultType, property, column, javaTypeClass, jdbcTypeEnum, nestedSelect, nestedResultMap, notNullColumn, columnPrefix, typeHandlerClass, flags, resultSet, foreignColumn, lazy);
  }

  /**
   * 4.5处理嵌套的result map
   * @param context
   * @param resultMappings
   * @return
   * @throws Exception
   */
  private String processNestedResultMappings(XNode context, List<ResultMapping> resultMappings) throws Exception {
	  //处理association|collection|case
    if ("association".equals(context.getName())
        || "collection".equals(context.getName())
        || "case".equals(context.getName())) {

//    	<resultMap id="blogResult" type="Blog">
//    	  <association property="author" column="author_id" javaType="Author" select="selectAuthor"/>
//    	</resultMap>
//如果不是嵌套查询
      if (context.getStringAttribute("select") == null) {
    	//则递归调用5.1 resultMapElement
        ResultMap resultMap = resultMapElement(context, resultMappings);
        return resultMap.getId();
      }
    }
    return null;
  }


  //6 配置sql(定义可重用的 SQL 代码段)
  private void sqlElement(List<XNode> list) throws Exception {
    if (configuration.getDatabaseId() != null) {
      sqlElement(list, configuration.getDatabaseId());
    }
    sqlElement(list, null);
  }

  //6.1 配置sql
//<sql id="userColumns"> id,username,password </sql>
  private void sqlElement(List<XNode> list, String requiredDatabaseId) throws Exception {
    for (XNode context : list) {
      String databaseId = context.getStringAttribute("databaseId");
      String id = context.getStringAttribute("id");
      id = builderAssistant.applyCurrentNamespace(id, false);
      //比较简单，就是将sql片段放入hashmap,不过此时还没有解析sql片段
      if (databaseIdMatchesCurrent(id, databaseId, requiredDatabaseId)) {
        sqlFragments.put(id, context);
      }
    }
  }

  private boolean databaseIdMatchesCurrent(String id, String databaseId, String requiredDatabaseId) {
    if (requiredDatabaseId != null) {
      if (!requiredDatabaseId.equals(databaseId)) {
        return false;
      }
    } else {
      if (databaseId != null) {
        return false;
      }
      // skip this fragment if there is a previous one with a not null databaseId
      //如果有重名的id了
      //<sql id="userColumns"> id,username,password </sql>
      if (this.sqlFragments.containsKey(id)) {
        XNode context = this.sqlFragments.get(id);
        //如果之前那个重名的sql id有databaseId，则false，否则难道true？这样新的sql覆盖老的sql？？？
        if (context.getStringAttribute("databaseId") != null) {
          return false;
        }
      }
    }
    return true;
  }

  //7.配置select|insert|update|delete
  private void buildStatementFromContext(List<XNode> list) {
    //调用7.1构建语句
    if (configuration.getDatabaseId() != null) {
      buildStatementFromContext(list, configuration.getDatabaseId());
    }
    buildStatementFromContext(list, null);
  }

  //7.1构建语句
  private void buildStatementFromContext(List<XNode> list, String requiredDatabaseId) {
    for (XNode context : list) {
      //构建所有语句,一个mapper下可以有很多select
      //语句比较复杂，核心都在这里面，所以调用XMLStatementBuilder
      final XMLStatementBuilder statementParser = new XMLStatementBuilder(configuration, builderAssistant, context, requiredDatabaseId);
      try {
        //核心XMLStatementBuilder.parseStatementNode
        statementParser.parseStatementNode();
      } catch (IncompleteElementException e) {
        //如果出现SQL语句不完整，把它记下来，塞到configuration去
        configuration.addIncompleteStatement(statementParser);
      }
    }
  }

  private void bindMapperForNamespace() {
    String namespace = builderAssistant.getCurrentNamespace();
    if (namespace != null) {
      Class<?> boundType = null;
      try {
        boundType = Resources.classForName(namespace);
      } catch (ClassNotFoundException e) {
        //ignore, bound type is not required
      }
      if (boundType != null) {
        if (!configuration.hasMapper(boundType)) {
          // Spring may not know the real resource name so we set a flag
          // to prevent loading again this resource from the mapper interface
          // look at MapperAnnotationBuilder#loadXmlResource
          configuration.addLoadedResource("namespace:" + namespace);
          configuration.addMapper(boundType);
        }
      }
    }
  }

  private void parsePendingResultMaps() {
    Collection<ResultMapResolver> incompleteResultMaps = configuration.getIncompleteResultMaps();
    synchronized (incompleteResultMaps) {
      Iterator<ResultMapResolver> iter = incompleteResultMaps.iterator();
      while (iter.hasNext()) {
        try {
          iter.next().resolve();
          iter.remove();
        } catch (IncompleteElementException e) {
          // ResultMap is still missing a resource...
        }
      }
    }
  }

  private void parsePendingChacheRefs() {
    Collection<CacheRefResolver> incompleteCacheRefs = configuration.getIncompleteCacheRefs();
    synchronized (incompleteCacheRefs) {
      Iterator<CacheRefResolver> iter = incompleteCacheRefs.iterator();
      while (iter.hasNext()) {
        try {
          iter.next().resolveCacheRef();
          iter.remove();
        } catch (IncompleteElementException e) {
          // Cache ref is still missing a resource...
        }
      }
    }
  }

  private void parsePendingStatements() {
    Collection<XMLStatementBuilder> incompleteStatements = configuration.getIncompleteStatements();
    synchronized (incompleteStatements) {
      Iterator<XMLStatementBuilder> iter = incompleteStatements.iterator();
      while (iter.hasNext()) {
        try {
          iter.next().parseStatementNode();
          iter.remove();
        } catch (IncompleteElementException e) {
          // Statement is still missing a resource...
        }
      }
    }
  }

}
