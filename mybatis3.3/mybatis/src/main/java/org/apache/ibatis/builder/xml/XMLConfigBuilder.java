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
package org.apache.ibatis.builder.xml;

import java.io.InputStream;
import java.io.Reader;
import java.util.Properties;

import javax.sql.DataSource;

import org.apache.ibatis.builder.BaseBuilder;
import org.apache.ibatis.builder.BuilderException;
import org.apache.ibatis.datasource.DataSourceFactory;
import org.apache.ibatis.executor.ErrorContext;
import org.apache.ibatis.executor.loader.ProxyFactory;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.mapping.DatabaseIdProvider;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.parsing.XNode;
import org.apache.ibatis.parsing.XPathParser;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.reflection.MetaClass;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.reflection.wrapper.ObjectWrapperFactory;
import org.apache.ibatis.session.AutoMappingBehavior;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ExecutorType;
import org.apache.ibatis.session.LocalCacheScope;
import org.apache.ibatis.transaction.TransactionFactory;
import org.apache.ibatis.type.JdbcType;

/**
 * XML配置构建器
 * @author Clinton Begin
 */
public class XMLConfigBuilder extends BaseBuilder {

  private boolean parsed;
  private XPathParser parser;
  private String environment;

  public XMLConfigBuilder(Reader reader) {
    this(reader, null, null);
  }

  public XMLConfigBuilder(Reader reader, String environment) {
    this(reader, environment, null);
  }

  //构造函数，转换成XPathParser再去调用构造函数
  public XMLConfigBuilder(Reader reader, String environment, Properties props) {
    //构造一个需要验证，XMLMapperEntityResolver的XPathParser
    this(new XPathParser(reader, true, props, new XMLMapperEntityResolver()), environment, props);
  }

  //以下3个一组
  public XMLConfigBuilder(InputStream inputStream) {
    this(inputStream, null, null);
  }

  public XMLConfigBuilder(InputStream inputStream, String environment) {
    this(inputStream, environment, null);
  }

  public XMLConfigBuilder(InputStream inputStream, String environment, Properties props) {
    this(new XPathParser(inputStream, true, props, new XMLMapperEntityResolver()), environment, props);
  }

  //上面6个构造函数最后都合流到这个函数，传递XPathParser
  private XMLConfigBuilder(XPathParser parser, String environment, Properties props) {
    //首先调用父类初始化Configuration
    super(new Configuration());
    //错误上下文设置成SQL Mapper Configuration(XML文件配置),以便后面出错了报错
    ErrorContext.instance().resource("SQL Mapper Configuration");
    //将Properties全部设置到Configuration里面去
    this.configuration.setVariables(props);
    this.parsed = false;
    this.environment = environment;
    this.parser = parser;
  }

  /**
   * 解析xml配置文件,生成Configuration类
   * @return
   */
  public Configuration parse() {
    //全局Configuration只会初始化一次,如果已经解析过了，报错
    if (parsed) {
      throw new BuilderException("Each XMLConfigBuilder can only be used once.");
    }
    parsed = true;
    //将配置文件整个/configuration节点内容传递给parseConfiguration()方法
    parseConfiguration(parser.evalNode("/configuration"));
    return configuration;
  }

  /**
   * 分步解析配置文件
   * @param root custom node for "/configuration"
   */
  private void parseConfiguration(XNode root) {
    try {
      //1.properties
      propertiesElement(root.evalNode("properties"));
      //2.类型别名
      typeAliasesElement(root.evalNode("typeAliases"));
      //3.插件
      pluginElement(root.evalNode("plugins"));
      //4.对象工厂
      objectFactoryElement(root.evalNode("objectFactory"));
      //5.对象包装工厂
      objectWrapperFactoryElement(root.evalNode("objectWrapperFactory"));
      //6.设置
      settingsElement(root.evalNode("settings"));
      //7.环境
      environmentsElement(root.evalNode("environments"));
      //8.databaseIdProvider
      databaseIdProviderElement(root.evalNode("databaseIdProvider"));
      //9.类型处理器
      typeHandlerElement(root.evalNode("typeHandlers"));
      //10.映射器
      mapperElement(root.evalNode("mappers"));
    } catch (Exception e) {
      throw new BuilderException("Error parsing SQL Mapper Configuration. Cause: " + e, e);
    }
  }

  /**
   * 1.properties
   *   <properties resource="org/mybatis/example/config.properties">
   *       <property name="username" value="dev_user"/>
   *       <property name="password" value="F2Fa3!33TYyg"/>
   *   </properties>
   * @param context 表示properties节点
   */
  private void propertiesElement(XNode context) throws Exception {
    if (context != null) {
      //1.配置文件中 properties 元素体内指定的属性首先被读取。
      Properties defaults = context.getChildrenAsProperties();
      //2.在properties 元素体内查找resource或者url,如果配置了还可以拿到一部分配置信息
      String resource = context.getStringAttribute("resource");
      String url = context.getStringAttribute("url");
      if (resource != null && url != null) {
        throw new BuilderException("The properties element cannot specify both a URL and a resource based property file reference.  Please specify one or the other.");
      }
      // 3、把resource或者url（只能配置一个）拿到的配置信息归并到Properties中，会覆盖已经存在的完全一样的属性。
      if (resource != null) {
        defaults.putAll(Resources.getResourceAsProperties(resource));
      } else if (url != null) {
        defaults.putAll(Resources.getUrlAsProperties(url));
      }
      // 4.把构建XMLConfigBuilder时放入configuration的Variables也全部加入Properties
      Properties vars = configuration.getVariables();
      if (vars != null) {
        defaults.putAll(vars);
      }
      // 5、XPathParser里备份一份用来进行其他的解析
      parser.setVariables(defaults);
      // 6、最后再把所有的配置信息放到configuration里
      configuration.setVariables(defaults);
    }
  }

  /**
   * 2.类型别名
   * <typeAliases>
   *   <typeAlias type="domain.blog.Author"/>
   *   <typeAlias type="domain.blog.Blog"/>
   *   <typeAlias alias="Comment" type="domain.blog.Comment"/>
   *   <typeAlias alias="Post" type="domain.blog.Post"/>
   *   <typeAlias alias="Section" type="domain.blog.Section"/>
   *   <typeAlias alias="Tag" type="domain.blog.Tag"/>
   * </typeAliases>
   *
   * or
   * <typeAliases>
   *   <package name="domain.blog"/>
   * </typeAliases>
   * @param parent 表示typeAliases节点
   */
  private void typeAliasesElement(XNode parent) {
    if (parent != null) {
      for (XNode child : parent.getChildren()) {
        // 1、如果是package
        if ("package".equals(child.getName())) {
          String typeAliasPackage = child.getStringAttribute("name");
          // 1.1、去包下找所有类,然后注册别名(有@Alias注解则用，没有则取类的simpleName)
          configuration.getTypeAliasRegistry().registerAliases(typeAliasPackage);
        } else {
          // 2、如果是typeAlias,直接拿到别名和类型
          String alias = child.getStringAttribute("alias");
          String type = child.getStringAttribute("type");
          try {
            Class<?> clazz = Resources.classForName(type);
            if (alias == null) {
              // 2.1、如果没配alias,那就直接取类的simpleName
              typeAliasRegistry.registerAlias(clazz);
            } else {
              // 2.2、如果配了alias就用
              typeAliasRegistry.registerAlias(alias, clazz);
            }
          } catch (ClassNotFoundException e) {
            throw new BuilderException("Error registering typeAlias for '" + alias + "'. Cause: " + e, e);
          }
        }
      }
    }
  }



  /**
   * 3.插件
   *      MyBatis 允许使用插件来拦截方法调用
   *     <plugins>
   *        <plugin interceptor="org.mybatis.example.ExamplePlugin">
   *          <property name="someProperty" value="100"/>
   *        </plugin>
   *     </plugins>
   * @param parent 表示plugins节点
   */
  private void pluginElement(XNode parent) throws Exception {
    if (parent != null) {
      // 循环遍历所有拦截器
      for (XNode child : parent.getChildren()) {
        // 1、获得拦截器的全限定名
        String interceptor = child.getStringAttribute("interceptor");
        // 2、获得拦截器的属性配置
        Properties properties = child.getChildrenAsProperties();
        // 3、拦截器实例化
        Interceptor interceptorInstance = (Interceptor) resolveClass(interceptor).newInstance();
        // 4、配置属性
        interceptorInstance.setProperties(properties);
        // 5、把他加到InterceptorChain
        configuration.addInterceptor(interceptorInstance);
      }
    }
  }

  /**
   * 4.对象工厂,可以自定义对象创建的方式,比如用对象池？
   * <objectFactory type="org.mybatis.example.ExampleObjectFactory">
   *   <property name="someProperty" value="100"/>
   * </objectFactory>
   @param context 表示objectFactory节点
   */
  private void objectFactoryElement(XNode context) throws Exception {
    if (context != null) {
      // 1、获得全限定名
      String type = context.getStringAttribute("type");
      // 2、获得对象工厂的所有配置
      Properties properties = context.getChildrenAsProperties();
      // 3、实例化
      ObjectFactory factory = (ObjectFactory) resolveClass(type).newInstance();
      // 4、设置属性
      factory.setProperties(properties);
      // 5、将对象工厂设置到配置文件中
      configuration.setObjectFactory(factory);
    }
  }

  /**
   * 5.对象包装工厂
   * <objectWrapperFactory type="org.mybatis.example.MapWrapperFactory"/>
   * @param context 表示objectWrapperFactory节点
   */
  private void objectWrapperFactoryElement(XNode context) throws Exception {
    if (context != null) {
      String type = context.getStringAttribute("type");
      ObjectWrapperFactory factory = (ObjectWrapperFactory) resolveClass(type).newInstance();
      configuration.setObjectWrapperFactory(factory);
    }
  }

  /**
   * 6.设置
   * <settings>
   *   <setting name="cacheEnabled" value="true"/>
   *   <setting name="lazyLoadingEnabled" value="true"/>
   *   <setting name="multipleResultSetsEnabled" value="true"/>
   *   <setting name="useColumnLabel" value="true"/>
   *   <setting name="useGeneratedKeys" value="false"/>
   *   <setting name="enhancementEnabled" value="false"/>
   *   <setting name="defaultExecutorType" value="SIMPLE"/>
   *   <setting name="defaultStatementTimeout" value="25000"/>
   *   <setting name="safeRowBoundsEnabled" value="false"/>
   *   <setting name="mapUnderscoreToCamelCase" value="false"/>
   *   <setting name="localCacheScope" value="SESSION"/>
   *   <setting name="jdbcTypeForNull" value="OTHER"/>
   *   <setting name="lazyLoadTriggerMethods" value="equals,clone,hashCode,toString"/>
   * </settings>
   * @param context settings节点
   */
  private void settingsElement(XNode context) throws Exception {
    if (context != null) {
      // 1、拿到所有配置 <name,value>
      Properties props = context.getChildrenAsProperties();
      // 2、先检查下是否在Configuration类里都有相应的setter方法（防止拼写错误）
      MetaClass metaConfig = MetaClass.forClass(Configuration.class);
      for (Object key : props.keySet()) {
        if (!metaConfig.hasSetter(String.valueOf(key))) {
          throw new BuilderException("The setting " + key + " is not known.  Make sure you spelled it correctly (case sensitive).");
        }
      }

      // 3、一个个设置属性,如果没有配置,提供了默认值

      //如何自动映射列到字段/ 属性
      configuration.setAutoMappingBehavior(AutoMappingBehavior.valueOf(props.getProperty("autoMappingBehavior", "PARTIAL")));
      //缓存
      configuration.setCacheEnabled(booleanValueOf(props.getProperty("cacheEnabled"), true));
      //延迟加载的核心技术就是用代理模式，CGLIB/JAVASSIST两者选一
      configuration.setProxyFactory((ProxyFactory) createInstance(props.getProperty("proxyFactory")));
      //延迟加载
      configuration.setLazyLoadingEnabled(booleanValueOf(props.getProperty("lazyLoadingEnabled"), false));
      //延迟加载时，每种属性是否还要按需加载
      configuration.setAggressiveLazyLoading(booleanValueOf(props.getProperty("aggressiveLazyLoading"), true));
      //允不允许多种结果集从一个单独 的语句中返回
      configuration.setMultipleResultSetsEnabled(booleanValueOf(props.getProperty("multipleResultSetsEnabled"), true));
      //使用列标签代替列名
      configuration.setUseColumnLabel(booleanValueOf(props.getProperty("useColumnLabel"), true));
      //允许 JDBC 支持生成的键
      configuration.setUseGeneratedKeys(booleanValueOf(props.getProperty("useGeneratedKeys"), true));
      //配置默认的执行器
      configuration.setDefaultExecutorType(ExecutorType.valueOf(props.getProperty("defaultExecutorType", "SIMPLE")));
      //超时时间
      configuration.setDefaultStatementTimeout(integerValueOf(props.getProperty("defaultStatementTimeout"), null));
      //是否将DB字段自动映射到驼峰式Java属性（A_COLUMN-->aColumn）
      configuration.setMapUnderscoreToCamelCase(booleanValueOf(props.getProperty("mapUnderscoreToCamelCase"), false));
      //允许嵌套语句上使用RowBounds
      configuration.setSafeRowBoundsEnabled(booleanValueOf(props.getProperty("safeRowBoundsEnabled"), true));
      //默认用session级别的缓存
      configuration.setLocalCacheScope(LocalCacheScope.valueOf(props.getProperty("localCacheScope", "SESSION")));
      //为null值设置jdbctype
      configuration.setJdbcTypeForNull(JdbcType.valueOf(props.getProperty("jdbcTypeForNull", "OTHER")));
      //Object的哪些方法将触发延迟加载
      configuration.setLazyLoadTriggerMethods(stringSetValueOf(props.getProperty("lazyLoadTriggerMethods"), "equals,clone,hashCode,toString"));
      //使用安全的ResultHandler
      configuration.setSafeResultHandlerEnabled(booleanValueOf(props.getProperty("safeResultHandlerEnabled"), true));
      //动态SQL生成语言所使用的脚本语言
      configuration.setDefaultScriptingLanguage(resolveClass(props.getProperty("defaultScriptingLanguage")));
      //当结果集中含有Null值时是否执行映射对象的setter或者Map对象的put方法。此设置对于原始类型如int,boolean等无效。
      configuration.setCallSettersOnNulls(booleanValueOf(props.getProperty("callSettersOnNulls"), true));
      //logger名字的前缀
      configuration.setLogPrefix(props.getProperty("logPrefix"));
      //显式定义用什么log框架，不定义则用默认的自动发现jar包机制
      configuration.setLogImpl(resolveClass(props.getProperty("logImpl")));
      //配置工厂
      configuration.setConfigurationFactory(resolveClass(props.getProperty("configurationFactory")));
    }
  }

  /**
   * 7.环境
   * 	<environments default="development">
   *
   * 	  <environment id="development">
   * 	    <transactionManager type="JDBC">
   * 	      <property name="..." value="..."/>
   * 	    </transactionManager>
   * 	    <dataSource type="POOLED">
   *          <property name="driver" value="${driver}"/>
   * 	      <property name="url" value="${url}"/>
   * 	      <property name="username" value="${username}"/>
   * 	      <property name="password" value="${password}"/>
   * 	    </dataSource>
   * 	  </environment>
   *
   * 	  <environment id="production">
   *     	  <transactionManager type="JDBC">
   *     	    <property name="..." value="..."/>
   *     	  </transactionManager>
   *     	  <dataSource type="POOLED">
   *            <property name="driver" value="${driver}"/>
   *     	    <property name="url" value="${url}"/>
   *     	    <property name="username" value="${username}"/>
   *     	    <property name="password" value="${password}"/>
   *     	  </dataSource>
   *      </environment>
   *
   * 	</environments>
   * @param context  environments节点
   */
  private void environmentsElement(XNode context) throws Exception {
    if (context != null) {
      // 1、如果没有指定环境，就到environments体内找默认环境
      if (environment == null) {
        environment = context.getStringAttribute("default");
      }
      // 2、遍历子节点
      for (XNode child : context.getChildren()) {
        // a、取出id的值
        String id = child.getStringAttribute("id");
		// b、判断是不是指定环境
        if (isSpecifiedEnvironment(id)) {
          // c、获得事务工厂
          TransactionFactory txFactory = transactionManagerElement(child.evalNode("transactionManager"));
          // d、获得数据源
          DataSourceFactory dsFactory = dataSourceElement(child.evalNode("dataSource"));
          DataSource dataSource = dsFactory.getDataSource();
          // e、构建Environment
          Environment.Builder environmentBuilder = new Environment.Builder(id).transactionFactory(txFactory).dataSource(dataSource);
          // 3、设置环境
          configuration.setEnvironment(environmentBuilder.build());
        }
      }
    }
  }

  /**
   * 7.1 比较id和environment是否相等
   * @param id 环境的唯一标识
   */
  private boolean isSpecifiedEnvironment(String id) {
    if (environment == null) {
      throw new BuilderException("No environment specified.");
    } else if (id == null) {
      throw new BuilderException("Environment requires an id attribute.");
    } else {
      return environment.equals(id);
    }
  }

  /**
   * 7.1 事务管理器,没有就抛异常
   * <transactionManager type="JDBC">
   *   <property name="..." value="..."/>
   * </transactionManager>
   * @param context transactionManager节点
   */
  private TransactionFactory transactionManagerElement(XNode context) throws Exception {
    if (context != null) {
      String type = context.getStringAttribute("type");
      Properties props = context.getChildrenAsProperties();
      //根据type="JDBC"解析返回适当的TransactionFactory
      TransactionFactory factory = (TransactionFactory) resolveClass(type).newInstance();
      factory.setProperties(props);
      return factory;
    }
    throw new BuilderException("Environment declaration requires a TransactionFactory.");
  }

  /**
   * 7.2 数据源,没有就抛出异常
   * <dataSource type="POOLED">
   *   <property name="driver" value="${driver}"/>
   *   <property name="url" value="${url}"/>
   *   <property name="username" value="${username}"/>
   *   <property name="password" value="${password}"/>
   * </dataSource>
   * @param context dataSource节点
   */
  private DataSourceFactory dataSourceElement(XNode context) throws Exception {
    if (context != null) {
      String type = context.getStringAttribute("type");
      Properties props = context.getChildrenAsProperties();
      DataSourceFactory factory = (DataSourceFactory) resolveClass(type).newInstance();
      factory.setProperties(props);
      return factory;
    }
    throw new BuilderException("Environment declaration requires a DataSourceFactory.");
  }

  /**
   * 8.databaseIdProvider,可以根据不同数据库执行不同的SQL，sql要加databaseId属性
   *    vendor (自动售货机)
   * 	<databaseIdProvider type="DB_VENDOR">
   * 	  <property name="SQLServer" value="sqlServer"/>
   * 	  <property name="DB2" value="db2"/>
   * 	  <property name="Oracle" value="oracle" />
   * 	  <property name="Mysql" value="mysql" />
   * 	</databaseIdProvider>
   * @param context databaseIdProvider节点
   */
  private void databaseIdProviderElement(XNode context) throws Exception {
    DatabaseIdProvider databaseIdProvider = null;
    if (context != null) {
      String type = context.getStringAttribute("type");
      Properties properties = context.getChildrenAsProperties();
      //"DB_VENDOR"-->VendorDatabaseIdProvider
      databaseIdProvider = (DatabaseIdProvider) resolveClass(type).newInstance();
      databaseIdProvider.setProperties(properties);
    }
    Environment environment = configuration.getEnvironment();
    if (environment != null && databaseIdProvider != null) {
      //使用数据源获取数据库产品名然后和预定义的property比较,如果匹配上就设置到configuration里
      String databaseId = databaseIdProvider.getDatabaseId(environment.getDataSource());
      configuration.setDatabaseId(databaseId);
    }
  }



  /**
   * 9.类型处理器
   *     <typeHandlers>
   *         <typeHandler javaType="String" jdbcType="VARCHAR" handler="org.mybatis.example.ExampleTypeHandler"/>
   *     </typeHandlers>
   * or
   * 	<typeHandlers>
   * 	  <package name="org.mybatis.example"/>
   * 	</typeHandlers>
   * @param parent  <typeHandlers>节点
   */
  private void typeHandlerElement(XNode parent) {
    if (parent != null) {
      for (XNode child : parent.getChildren()) {
        // 1、如果是package
        if ("package".equals(child.getName())) {
          String typeHandlerPackage = child.getStringAttribute("name");
          // 1.1、去包下找所有类，然后注册到别名注册表
          typeHandlerRegistry.register(typeHandlerPackage);
        } else {
          // 2、如果是typeHandler,找到需要的信息,也注册到别名注册表中
          String javaTypeName = child.getStringAttribute("javaType");
          String jdbcTypeName = child.getStringAttribute("jdbcType");
          String handlerTypeName = child.getStringAttribute("handler");
          Class<?> javaTypeClass = resolveClass(javaTypeName);
          JdbcType jdbcType = resolveJdbcType(jdbcTypeName);
          Class<?> typeHandlerClass = resolveClass(handlerTypeName);
          if (javaTypeClass != null) {
            if (jdbcType == null) {
              typeHandlerRegistry.register(javaTypeClass, typeHandlerClass);
            } else {
              typeHandlerRegistry.register(javaTypeClass, jdbcType, typeHandlerClass);
            }
          } else {
            typeHandlerRegistry.register(typeHandlerClass);
          }
        }
      }
    }
  }

  /**
   * 10.解析Dao层和映射文件
   *
   *    第一类：dao层 (一般不配置，因为mappers文件里面有个namespace,记录了dao层类的全限定名)
   *      a、通常我们是放到一个包里,然后自动扫描包下所有映射器
   *      <mappers>
   *        <package name="org.mybatis.builder"/>
   *      </mappers>
   *
   *      b、使用java类名
   *      <mappers>
   *    	    <mapper class="org.mybatis.builder.AuthorMapper"/>
   *    	    <mapper class="org.mybatis.builder.BlogMapper"/>
   *    	    <mapper class="org.mybatis.builder.PostMapper"/>
   *      </mappers>
   *
   *    第二类：mappers.xml文件
   * 	  c、使用相对路径,注意目录结构必须以斜杠分割,需要XMLMapperBuilder来解析
   * 	  <mappers>
   * 	    <mapper resource="org/mybatis/builder/AuthorMapper.xml"/>
   * 	    <mapper resource="org/mybatis/builder/BlogMapper.xml"/>
   * 	    <mapper resource="org/mybatis/builder/PostMapper.xml"/>
   * 	  </mappers>
   *
   * 	  d、使用绝对url路径，需要XMLMapperBuilder来解析
   * 	  <mappers>
   * 	    <mapper url="file:///var/mappers/AuthorMapper.xml"/>
   * 	    <mapper url="file:///var/mappers/BlogMapper.xml"/>
   * 	    <mapper url="file:///var/mappers/PostMapper.xml"/>
   * 	  </mappers>
   * @param parent <mappers>节点
   */
  private void mapperElement(XNode parent) throws Exception {
    if (parent != null) {
      for (XNode child : parent.getChildren()) {
        if ("package".equals(child.getName())) {
          // 1、扫描包下所有接口,将所有接口都注册进映射接口表
          String mapperPackage = child.getStringAttribute("name");
          configuration.addMappers(mapperPackage);
        } else {
          String resource = child.getStringAttribute("resource");
          String url = child.getStringAttribute("url");
          String mapperClass = child.getStringAttribute("class");
          if (resource != null && url == null && mapperClass == null) {
            // 2、使用相对路径解析xml
            ErrorContext.instance().resource(resource);
            InputStream inputStream = Resources.getResourceAsStream(resource);
            // 调用XMLMapperBuilder来解析
            XMLMapperBuilder mapperParser = new XMLMapperBuilder(inputStream, configuration, resource, configuration.getSqlFragments());
            mapperParser.parse();
          } else if (resource == null && url != null && mapperClass == null) {
            // 3、使用绝对路径解析xml
            ErrorContext.instance().resource(url);
            InputStream inputStream = Resources.getUrlAsStream(url);
            // 调用XMLMapperBuilder来解析
            XMLMapperBuilder mapperParser = new XMLMapperBuilder(inputStream, configuration, url, configuration.getSqlFragments());
            mapperParser.parse();
          } else if (resource == null && url == null && mapperClass != null) {
            Class<?> mapperInterface = Resources.classForName(mapperClass);
            // 4、使用全限定名，将类注册进映射接口表
            configuration.addMapper(mapperInterface);
          } else {
            throw new BuilderException("A mapper element may only specify a url, resource or class, but not more than one.");
          }
        }
      }
    }
  }

}
