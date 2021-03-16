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
package org.apache.ibatis.builder.annotation;

import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.ibatis.annotations.Arg;
import org.apache.ibatis.annotations.CacheNamespace;
import org.apache.ibatis.annotations.CacheNamespaceRef;
import org.apache.ibatis.annotations.Case;
import org.apache.ibatis.annotations.ConstructorArgs;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.DeleteProvider;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.InsertProvider;
import org.apache.ibatis.annotations.Lang;
import org.apache.ibatis.annotations.MapKey;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.ResultMap;
import org.apache.ibatis.annotations.ResultType;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.SelectKey;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.TypeDiscriminator;
import org.apache.ibatis.annotations.Update;
import org.apache.ibatis.annotations.UpdateProvider;
import org.apache.ibatis.binding.BindingException;
import org.apache.ibatis.binding.MapperMethod.ParamMap;
import org.apache.ibatis.builder.BuilderException;
import org.apache.ibatis.builder.IncompleteElementException;
import org.apache.ibatis.builder.MapperBuilderAssistant;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.executor.keygen.Jdbc3KeyGenerator;
import org.apache.ibatis.executor.keygen.KeyGenerator;
import org.apache.ibatis.executor.keygen.NoKeyGenerator;
import org.apache.ibatis.executor.keygen.SelectKeyGenerator;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.mapping.Discriminator;
import org.apache.ibatis.mapping.FetchType;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ResultFlag;
import org.apache.ibatis.mapping.ResultMapping;
import org.apache.ibatis.mapping.ResultSetType;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.mapping.StatementType;
import org.apache.ibatis.scripting.LanguageDriver;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.TypeHandler;
import org.apache.ibatis.type.UnknownTypeHandler;

/**
 * mapper注解构建器,解析当前Class<?>(Dao层接口)中包含的所有mybatis框架中定义的注解，并生成Cache、ResultMap、MappedStatement三种类型对象。
 * 注解配置是xml方式配置的子集，且配置后不易修改和查看，因此还是建议用户使用xml的方式来配置mapper。不建议使用注解方式。
 * @author Clinton Begin
 * @blog "https://blog.csdn.net/weixin_34220623/article/details/91905968
 */
public class MapperAnnotationBuilder {
  /**
   * 4个元素 @Select、@Insert、@Update、@Delete,sql语句保存在注解中
   * eq:  @Select("select p.person_name as name,p.age,p.phone,p.email,p.address from person p where p.id = #{id}")
   */
  private final Set<Class<? extends Annotation>> sqlAnnotationTypes = new HashSet<>();

  /**
   * 4个元素：@SelectProvider、@InsertProvider、@UpdateProvider、@DeleteProvider , sql语句保存在注解指定的类的指定方法中
   * eq:
   *   Dao层   @SelectProvider(type=BaseUserProvider.class,method="selectUserById")
   *           public BaseUser selectById(@Param(value="id")Integer id);
   *
   *   BaseUserProvider类中selectUserById方法
   *           public String selectUserById(Map<String, Object> para){
   *               return "select * from base_user where id =" +para.get("id");
   *            }
   */
  private final Set<Class<? extends Annotation>> sqlProviderAnnotationTypes = new HashSet<>();

  // 核心配置对象
  private Configuration configuration;
  // Mapper构建助手,用于组装解析出来的配置，生成Cache、ResultMap、MappedStatement等对象，并添加到Configuration配置对象中
  private MapperBuilderAssistant assistant;
  // 要解析的目标接口的Class对象
  private Class<?> type;

  public MapperAnnotationBuilder(Configuration configuration, Class<?> type) {
    // "com.mybatis.lizx.dao.PersonDao" ---> "com/mybatis/lizx/dao/PersonDao.java (best guess)"
    String resource = type.getName().replace('.', '/') + ".java (best guess)";

    // 处理缓存，不知道这里在干啥？？
    // 每个mapper注解构建器实例内部都构造了一个映射构造器助手
    this.assistant = new MapperBuilderAssistant(configuration, resource);
    this.configuration = configuration;
    this.type = type;

    // 添加注解类型
    sqlAnnotationTypes.add(Select.class);
    sqlAnnotationTypes.add(Insert.class);
    sqlAnnotationTypes.add(Update.class);
    sqlAnnotationTypes.add(Delete.class);

    sqlProviderAnnotationTypes.add(SelectProvider.class);
    sqlProviderAnnotationTypes.add(InsertProvider.class);
    sqlProviderAnnotationTypes.add(UpdateProvider.class);
    sqlProviderAnnotationTypes.add(DeleteProvider.class);
  }

  /**
   * parse解析xml与注解
   * 解析配置文件是在MapperAnnotationBuilder类的parse方法里完成的，该方法先解析配置文件，然后再解析接口里的注解配置，
   * 且注解里的配置会覆盖配置文件里的配置，也就是说注解的优先级高于配置文件，
   * 这点需要注意。采用自动扫描会大大简化配置，只不过需要应用程序自己调用，mybatis默认是不会调用这个方法的，
   * mybatis与spring的整合的自动扫描就调用到了这个方法
   */
  public void parse() {
    // 以Class.toString()方法生成的字符串，作为Class对象的唯一标识,如interface com.mybatis.lizx.dao.PersonDao
    String resource = type.toString();
    // 如果当前Class对象已经解析过，则不再解析
    if (!configuration.isResourceLoaded(resource)) {
      // 加载并解析指定的xml配置文件
      loadXmlResource();
      // 把Class对应的唯一标识添加到已加载的资源列表中,以防止重复解析。
      configuration.addLoadedResource(resource);
      // 设置当前namespace为接口Class的全限定名,即com.mybatis.lizx.dao.PersonDao
      assistant.setCurrentNamespace(type.getName());
      // 二级缓存的处理,parseCache()与parseCacheRef()都是设置二级缓存，分别处理注解@CacheNamespace与@CacheNamespaceRef。
      // 顾名思义，二级缓存与命名空间有关，其实是缓存sql查询结果，范围是同一命名空间
      // 解析缓存对象
      parseCache();
      // 解析缓存引用，会覆盖之前解析的缓存对象
      parseCacheRef();
      // 获取所有方法，解析方法上的注解，生成MappedStatement和ResultMap
      Method[] methods = type.getMethods();
      // 遍历所有获取到的方法
      for (Method method : methods) {
        try {
          if (!method.isBridge()) {
            // 解析一个方法生成对应的MapperedStatement对象,并添加到配置对象中
            parseStatement(method);
          }
        } catch (IncompleteElementException e) {
          configuration.addIncompleteMethod(new MethodResolver(this, method));
        }
      }
    }
    // 解析挂起的方法
    parsePendingMethods();
  }

  private void parsePendingMethods() {
    Collection<MethodResolver> incompleteMethods = configuration.getIncompleteMethods();
    synchronized (incompleteMethods) {
      Iterator<MethodResolver> iter = incompleteMethods.iterator();
      while (iter.hasNext()) {
        try {
          iter.next().resolve();
          iter.remove();
        } catch (IncompleteElementException e) {
          // This method is still missing a resource
        }
      }
    }
  }

  private void loadXmlResource() {
    // XMLMapperBuilder每解析一个xml配置文件,都会以文件所在路径为xml文件的唯一标识，并把标识添加到已加载的资源文件列表中
    // 而loadXmlResource()方法中避免重复加载检查的key的却是"namespace:"+类全限定名的格式。为什么？
    /*
    * 之所以使用这种方式，是因为当前并不知道xml文件的真实名称是什么，与Class全限定名只是约定（换句话说，xml文件路径完全可以不遵循这种约定）。
    * 因此，为了避免重复加载，XMLMapperBuilder在解析完配置文件后，会调用bindMapperForNamespace()方法，
    * 尝试加载配置文件中根元素的namespace属性获取Class对象，并且添加"namespace:"+全限定名格式的额外的key到已加载资源列表中，来通知MapperAnnotationBuilder。
    * */

    // 如果已加载资源列表中指定key已存在，则不再解析xml文件,资源名称为 namespace:全限定名
    if (!configuration.isResourceLoaded("namespace:" + type.getName())) {
      // 根据Class对象生成xml配置文件路径
      // 以Class所在的包对应文件路径，Class类名对应文件名称来找xml，如：com.mybatis.lizx.dao.PersonDao类对应的配置文件为com/mybatis/lizx/dao/PersonDao.xml
      String xmlResource = type.getName().replace('.', '/') + ".xml";
      InputStream inputStream = null;
      try {
        // 获取文件字节流
        inputStream = Resources.getResourceAsStream(type.getClassLoader(), xmlResource);
      } catch (IOException ignored) {}
      if (inputStream != null) {
        // 如果xml文件存在，则创建XMLMapperBuilder进行解析
        XMLMapperBuilder xmlParser = new XMLMapperBuilder(inputStream, assistant.getConfiguration(), xmlResource, configuration.getSqlFragments(), type.getName());
        // 解析xml文件
        xmlParser.parse();
      }
    }
  }

  /**
   * 注意：@CacheNamespace注解对应mapper.xml配置文件中的<cache>元素，但是注解方式不支持properties自定义属性的配置。
   */
  private void parseCache() {
    // 获取接口上的@CacheNamespace注解
    CacheNamespace cacheDomain = type.getAnnotation(CacheNamespace.class);
    // 如果存在该注解，则调用构建助手创建缓存对象
    if (cacheDomain != null) {
      Integer size = cacheDomain.size() == 0 ? null : cacheDomain.size();
      Long flushInterval = cacheDomain.flushInterval() == 0 ? null : cacheDomain.flushInterval();
      assistant.useNewCache(cacheDomain.implementation(), cacheDomain.eviction(), flushInterval, size, cacheDomain.readWrite(), cacheDomain.blocking(), null);
    }
  }

  /**
   * 注意 @CacheNamespaceRef注解对应mapper.xml配置文件中的<cache-ref namespace=""/>元素。
   */
  private void parseCacheRef() {
    // 获取接口上的@CacheNamespaceRef注解
    CacheNamespaceRef cacheDomainRef = type.getAnnotation(CacheNamespaceRef.class);
    // 如果存在该注解，则调用构建助手添加引用关系，以Class对象的全限定名为目标namespace
    if (cacheDomainRef != null) {
      assistant.useCacheRef(cacheDomainRef.value().getName());
    }
  }

  private String parseResultMap(Method method) {
    // 获取目标bean的类型
    Class<?> returnType = getReturnType(method);
    // 获取方法上的@ConstructorArgs注解
    ConstructorArgs args = method.getAnnotation(ConstructorArgs.class);
    // 获取方法上的@Results
    Results results = method.getAnnotation(Results.class);
    // 获取方法上的@TypeDiscriminator注解
    TypeDiscriminator typeDiscriminator = method.getAnnotation(TypeDiscriminator.class);
    // 根据方法生成resultMap的唯一标识，格式为：类全限定名.方法名-参数类型简单名称
    String resultMapId = generateResultMapName(method);
    // resultMapId和返回值类型已经解析完毕，
    // 再解析剩下的构造方法映射、属性映射和鉴别器，之后添加结果映射到配置对象中
    applyResultMap(resultMapId, returnType, argsIf(args), resultsIf(results), typeDiscriminator);
    return resultMapId;
  }

  private String generateResultMapName(Method method) {
    StringBuilder suffix = new StringBuilder();
    for (Class<?> c : method.getParameterTypes()) {
      suffix.append("-");
      suffix.append(c.getSimpleName());
    }
    if (suffix.length() < 1) {
      suffix.append("-void");
    }
    return type.getName() + "." + method.getName() + suffix;
  }

  private void applyResultMap(String resultMapId, Class<?> returnType, Arg[] args, Result[] results, TypeDiscriminator discriminator) {
    List<ResultMapping> resultMappings = new ArrayList<ResultMapping>();
    applyConstructorArgs(args, returnType, resultMappings);
    applyResults(results, returnType, resultMappings);
    Discriminator disc = applyDiscriminator(resultMapId, returnType, discriminator);
    // TODO add AutoMappingBehaviour
    assistant.addResultMap(resultMapId, returnType, null, disc, resultMappings, null);
    createDiscriminatorResultMaps(resultMapId, returnType, discriminator);
  }

  private void createDiscriminatorResultMaps(String resultMapId, Class<?> resultType, TypeDiscriminator discriminator) {
    if (discriminator != null) {
      for (Case c : discriminator.cases()) {
        String caseResultMapId = resultMapId + "-" + c.value();
        List<ResultMapping> resultMappings = new ArrayList<ResultMapping>();
        // issue #136
        applyConstructorArgs(c.constructArgs(), resultType, resultMappings);
        applyResults(c.results(), resultType, resultMappings);
        // TODO add AutoMappingBehaviour
        assistant.addResultMap(caseResultMapId, c.type(), resultMapId, null, resultMappings, null);
      }
    }
  }

  private Discriminator applyDiscriminator(String resultMapId, Class<?> resultType, TypeDiscriminator discriminator) {
    if (discriminator != null) {
      String column = discriminator.column();
      Class<?> javaType = discriminator.javaType() == void.class ? String.class : discriminator.javaType();
      JdbcType jdbcType = discriminator.jdbcType() == JdbcType.UNDEFINED ? null : discriminator.jdbcType();
      Class<? extends TypeHandler<?>> typeHandler = discriminator.typeHandler() == UnknownTypeHandler.class ? null : discriminator.typeHandler();
      Case[] cases = discriminator.cases();
      Map<String, String> discriminatorMap = new HashMap<String, String>();
      for (Case c : cases) {
        String value = c.value();
        String caseResultMapId = resultMapId + "-" + value;
        discriminatorMap.put(value, caseResultMapId);
      }
      return assistant.buildDiscriminator(resultType, column, javaType, jdbcType, typeHandler, discriminatorMap);
    }
    return null;
  }

  /**
   * MapperAnnotationBuilder会遍历Class对象中的所有方法，一个Method对象对应一个MappedStatement对象，
   * ResultMap的定义与xml配置文件方式不同，配置文件由单独的<resultMap>元素定义，
   * 而注解方式则定义在方法上。每个方法可以创建新的ResultMap对象，也可以引用已经存在的ResultMap对象的id。
   */
  void parseStatement(Method method) {
    // 获取输入参数的类型,排除掉RowBounds和 ResultHandler
    Class<?> parameterTypeClass = getParameterType(method);
    // 通过方法上的@Lang注解获取语言驱动
    LanguageDriver languageDriver = getLanguageDriver(method);
    // 通过方法上的@Select等注解获取SqlSource
    SqlSource sqlSource = getSqlSourceFromAnnotations(method, parameterTypeClass, languageDriver);
    // 如果成功创建了SqlSource，则继续
    if (sqlSource != null) {
      // 获取方法上的@Options注解
      Options options = method.getAnnotation(Options.class);
      // 映射语句id为类的全限定名.方法名
      final String mappedStatementId = type.getName() + "." + method.getName();
      Integer fetchSize = null;
      Integer timeout = null;
      StatementType statementType = StatementType.PREPARED;
      ResultSetType resultSetType = ResultSetType.FORWARD_ONLY;
      // 通过注解获取Sql命令类型
      SqlCommandType sqlCommandType = getSqlCommandType(method);
      boolean isSelect = sqlCommandType == SqlCommandType.SELECT;
      boolean flushCache = !isSelect;
      boolean useCache = isSelect;

      KeyGenerator keyGenerator;
      String keyProperty = "id";
      String keyColumn = null;
      // 如果是insert或update命令
      if (SqlCommandType.INSERT.equals(sqlCommandType) || SqlCommandType.UPDATE.equals(sqlCommandType)) {
        // 首先检查@SelectKey注解 ，它会覆盖任何其他的配置,获取方法上的SelectKey注解
        SelectKey selectKey = method.getAnnotation(SelectKey.class);
        // 如果存在@SelectKey注解
        if (selectKey != null) {
          keyGenerator = handleSelectKeyAnnotation(selectKey, mappedStatementId, getParameterType(method), languageDriver);
          keyProperty = selectKey.keyProperty();
        } else if (options == null) {
          keyGenerator = configuration.isUseGeneratedKeys() ? new Jdbc3KeyGenerator() : new NoKeyGenerator();
        } else {
          keyGenerator = options.useGeneratedKeys() ? new Jdbc3KeyGenerator() : new NoKeyGenerator();
          keyProperty = options.keyProperty();
          keyColumn = options.keyColumn();
        }
      } else {
        // 其他sql命令均没有键生成器
        keyGenerator = new NoKeyGenerator();
      }

      if (options != null) {
        flushCache = options.flushCache();
        useCache = options.useCache();
        fetchSize = options.fetchSize() > -1 || options.fetchSize() == Integer.MIN_VALUE ? options.fetchSize() : null; //issue #348
        timeout = options.timeout() > -1 ? options.timeout() : null;
        statementType = options.statementType();
        resultSetType = options.resultSetType();
      }
      // 处理方法上的@ResultMap注解
      String resultMapId = null;
      // 获取注解，@ResultMap注解代表引用已经存在的resultMap对象的id
      ResultMap resultMapAnnotation = method.getAnnotation(ResultMap.class);
      // 如果方法上存在@ResultMap注解，则生成引用id即可
      if (resultMapAnnotation != null) {
        // 获取指定的多个resultMapId
        String[] resultMaps = resultMapAnnotation.value();
        StringBuilder sb = new StringBuilder();
        // 遍历String数组，拼接为一个String，逗号分隔
        for (String resultMap : resultMaps) {
          if (sb.length() > 0) {
            sb.append(",");
          }
          sb.append(resultMap);
        }
        resultMapId = sb.toString();
      } else if (isSelect) {
        // 不存在@ResultMap注解，且语句为select类型，
        // 则通过解析@Args、@Results等注解生成新的ResultMap对象
        resultMapId = parseResultMap(method);
      }
      // 构建MappedStatement并添加到配置对象中
      assistant.addMappedStatement(
          mappedStatementId,
          sqlSource,
          statementType,
          sqlCommandType,
          fetchSize,
          timeout,
          // ParameterMapID
          null,
          parameterTypeClass,
          resultMapId,
          getReturnType(method),
          resultSetType,
          flushCache,
          useCache,
          // TODO issue #577
          false,
          keyGenerator,
          keyProperty,
          keyColumn,
          // DatabaseID
          null,
          languageDriver,
          // ResultSets
          null);

      /*从代码逻辑可以看出，如果不存在@Select、@Insert、@Update、@Delete或者对应的@xxxProvider中的任何一个，则后续注解全是无效，
      只有@Lang会起作用。当使用@ResultMap注解引用已存在的结果映射时，后续关于创建新的结果映射的注解将失效。*/
    }
  }

  /**
   * 通过方法上的@Lang注解获取语言驱动
   * @param method
   * @return
   */
  private LanguageDriver getLanguageDriver(Method method) {
    Lang lang = method.getAnnotation(Lang.class);
    Class<?> langClass = null;
    if (lang != null) {
      langClass = lang.value();
    }
    return assistant.getLanguageDriver(langClass);
  }

  /**
   * 获取输入参数的类型,
   */
  private Class<?> getParameterType(Method method) {
    Class<?> parameterType = null;
    Class<?>[] parameterTypes = method.getParameterTypes();
    for (int i = 0; i < parameterTypes.length; i++) {
      // 排除掉RowBounds和 ResultHandler
      if (!RowBounds.class.isAssignableFrom(parameterTypes[i]) && !ResultHandler.class.isAssignableFrom(parameterTypes[i])) {
        if (parameterType == null) {
          // 如果只有单个参数,不是RowBounds和 ResultHandler，那就返回这个参数的类型
          parameterType = parameterTypes[i];
        } else {
          // 如果有多个参数,不是RowBounds和 ResultHandler，那就返回ParamMap.class
          parameterType = ParamMap.class;
        }
      }
    }
    return parameterType;
  }

  private Class<?> getReturnType(Method method) {
    Class<?> returnType = method.getReturnType();
    // issue #508
    if (void.class.equals(returnType)) {
      ResultType rt = method.getAnnotation(ResultType.class);
      if (rt != null) {
        returnType = rt.value();
      }
    } else if (Collection.class.isAssignableFrom(returnType)) {
      Type returnTypeParameter = method.getGenericReturnType();
      if (returnTypeParameter instanceof ParameterizedType) {
        Type[] actualTypeArguments = ((ParameterizedType) returnTypeParameter).getActualTypeArguments();
        if (actualTypeArguments != null && actualTypeArguments.length == 1) {
          returnTypeParameter = actualTypeArguments[0];
          if (returnTypeParameter instanceof Class) {
            returnType = (Class<?>) returnTypeParameter;
          } else if (returnTypeParameter instanceof ParameterizedType) {
            // (issue #443) actual type can be a also a parameterized type
            returnType = (Class<?>) ((ParameterizedType) returnTypeParameter).getRawType();
          } else if (returnTypeParameter instanceof GenericArrayType) {
            Class<?> componentType = (Class<?>) ((GenericArrayType) returnTypeParameter).getGenericComponentType();
            // (issue #525) support List<byte[]>
            returnType = Array.newInstance(componentType, 0).getClass();
          }
        }
      }
    } else if (method.isAnnotationPresent(MapKey.class) && Map.class.isAssignableFrom(returnType)) {
      // (issue 504) Do not look into Maps if there is not MapKey annotation
      Type returnTypeParameter = method.getGenericReturnType();
      if (returnTypeParameter instanceof ParameterizedType) {
        Type[] actualTypeArguments = ((ParameterizedType) returnTypeParameter).getActualTypeArguments();
        if (actualTypeArguments != null && actualTypeArguments.length == 2) {
          returnTypeParameter = actualTypeArguments[1];
          if (returnTypeParameter instanceof Class) {
            returnType = (Class<?>) returnTypeParameter;
          } else if (returnTypeParameter instanceof ParameterizedType) {
            // (issue 443) actual type can be a also a parameterized type
            returnType = (Class<?>) ((ParameterizedType) returnTypeParameter).getRawType();
          }
        }
      }
    }

    return returnType;
  }

  /**
   * 通过方法上的@Select等注解获取SqlSource
   */
  private SqlSource getSqlSourceFromAnnotations(Method method, Class<?> parameterType, LanguageDriver languageDriver) {
    try {
      Class<? extends Annotation> sqlAnnotationType = getSqlAnnotationType(method);
      Class<? extends Annotation> sqlProviderAnnotationType = getSqlProviderAnnotationType(method);
      if (sqlAnnotationType != null) {
        if (sqlProviderAnnotationType != null) {
          throw new BindingException("You cannot supply both a static SQL and SqlProvider to method named " + method.getName());
        }
        Annotation sqlAnnotation = method.getAnnotation(sqlAnnotationType);
        final String[] strings = (String[]) sqlAnnotation.getClass().getMethod("value").invoke(sqlAnnotation);
        return buildSqlSourceFromStrings(strings, parameterType, languageDriver);
      } else if (sqlProviderAnnotationType != null) {
        Annotation sqlProviderAnnotation = method.getAnnotation(sqlProviderAnnotationType);
        return new ProviderSqlSource(assistant.getConfiguration(), sqlProviderAnnotation);
      }
      return null;
    } catch (Exception e) {
      throw new BuilderException("Could not find value method on SQL annotation.  Cause: " + e, e);
    }
  }

  private SqlSource buildSqlSourceFromStrings(String[] strings, Class<?> parameterTypeClass, LanguageDriver languageDriver) {
    final StringBuilder sql = new StringBuilder();
    for (String fragment : strings) {
      sql.append(fragment);
      sql.append(" ");
    }
    return languageDriver.createSqlSource(configuration, sql.toString(), parameterTypeClass);
  }

  private SqlCommandType getSqlCommandType(Method method) {
    Class<? extends Annotation> type = getSqlAnnotationType(method);

    if (type == null) {
      type = getSqlProviderAnnotationType(method);

      if (type == null) {
        return SqlCommandType.UNKNOWN;
      }

      if (type == SelectProvider.class) {
        type = Select.class;
      } else if (type == InsertProvider.class) {
        type = Insert.class;
      } else if (type == UpdateProvider.class) {
        type = Update.class;
      } else if (type == DeleteProvider.class) {
        type = Delete.class;
      }
    }

    return SqlCommandType.valueOf(type.getSimpleName().toUpperCase(Locale.ENGLISH));
  }

  private Class<? extends Annotation> getSqlAnnotationType(Method method) {
    return chooseAnnotationType(method, sqlAnnotationTypes);
  }

  private Class<? extends Annotation> getSqlProviderAnnotationType(Method method) {
    return chooseAnnotationType(method, sqlProviderAnnotationTypes);
  }

  private Class<? extends Annotation> chooseAnnotationType(Method method, Set<Class<? extends Annotation>> types) {
    for (Class<? extends Annotation> type : types) {
      Annotation annotation = method.getAnnotation(type);
      if (annotation != null) {
        return type;
      }
    }
    return null;
  }

  private void applyResults(Result[] results, Class<?> resultType, List<ResultMapping> resultMappings) {
    for (Result result : results) {
      List<ResultFlag> flags = new ArrayList<ResultFlag>();
      if (result.id()) {
        flags.add(ResultFlag.ID);
      }
      ResultMapping resultMapping = assistant.buildResultMapping(
          resultType,
          nullOrEmpty(result.property()),
          nullOrEmpty(result.column()),
          result.javaType() == void.class ? null : result.javaType(),
          result.jdbcType() == JdbcType.UNDEFINED ? null : result.jdbcType(),
          hasNestedSelect(result) ? nestedSelectId(result) : null,
          null,
          null,
          null,
          result.typeHandler() == UnknownTypeHandler.class ? null : result.typeHandler(),
          flags,
          null,
          null,
          isLazy(result));
      resultMappings.add(resultMapping);
    }
  }

  private String nestedSelectId(Result result) {
    String nestedSelect = result.one().select();
    if (nestedSelect.length() < 1) {
      nestedSelect = result.many().select();
    }
    if (!nestedSelect.contains(".")) {
      nestedSelect = type.getName() + "." + nestedSelect;
    }
    return nestedSelect;
  }

  private boolean isLazy(Result result) {
    boolean isLazy = configuration.isLazyLoadingEnabled();
    if (result.one().select().length() > 0 && FetchType.DEFAULT != result.one().fetchType()) {
      isLazy = (result.one().fetchType() == FetchType.LAZY);
    } else if (result.many().select().length() > 0 && FetchType.DEFAULT != result.many().fetchType()) {
      isLazy = (result.many().fetchType() == FetchType.LAZY);
    }
    return isLazy;
  }

  private boolean hasNestedSelect(Result result) {
    if (result.one().select().length() > 0 && result.many().select().length() > 0) {
      throw new BuilderException("Cannot use both @One and @Many annotations in the same @Result");
    }
    return result.one().select().length() > 0 || result.many().select().length() > 0;
  }

  private void applyConstructorArgs(Arg[] args, Class<?> resultType, List<ResultMapping> resultMappings) {
    for (Arg arg : args) {
      List<ResultFlag> flags = new ArrayList<ResultFlag>();
      flags.add(ResultFlag.CONSTRUCTOR);
      if (arg.id()) {
        flags.add(ResultFlag.ID);
      }
      ResultMapping resultMapping = assistant.buildResultMapping(
          resultType,
          null,
          nullOrEmpty(arg.column()),
          arg.javaType() == void.class ? null : arg.javaType(),
          arg.jdbcType() == JdbcType.UNDEFINED ? null : arg.jdbcType(),
          nullOrEmpty(arg.select()),
          nullOrEmpty(arg.resultMap()),
          null,
          null,
          arg.typeHandler() == UnknownTypeHandler.class ? null : arg.typeHandler(),
          flags,
          null,
          null,
          false);
      resultMappings.add(resultMapping);
    }
  }

  private String nullOrEmpty(String value) {
    return value == null || value.trim().length() == 0 ? null : value;
  }

  private Result[] resultsIf(Results results) {
    return results == null ? new Result[0] : results.value();
  }

  private Arg[] argsIf(ConstructorArgs args) {
    return args == null ? new Arg[0] : args.value();
  }

  private KeyGenerator handleSelectKeyAnnotation(SelectKey selectKeyAnnotation, String baseStatementId, Class<?> parameterTypeClass, LanguageDriver languageDriver) {
    String id = baseStatementId + SelectKeyGenerator.SELECT_KEY_SUFFIX;
    Class<?> resultTypeClass = selectKeyAnnotation.resultType();
    StatementType statementType = selectKeyAnnotation.statementType();
    String keyProperty = selectKeyAnnotation.keyProperty();
    String keyColumn = selectKeyAnnotation.keyColumn();
    boolean executeBefore = selectKeyAnnotation.before();

    // defaults
    boolean useCache = false;
    KeyGenerator keyGenerator = new NoKeyGenerator();
    Integer fetchSize = null;
    Integer timeout = null;
    boolean flushCache = false;
    String parameterMap = null;
    String resultMap = null;
    ResultSetType resultSetTypeEnum = null;

    SqlSource sqlSource = buildSqlSourceFromStrings(selectKeyAnnotation.statement(), parameterTypeClass, languageDriver);
    SqlCommandType sqlCommandType = SqlCommandType.SELECT;

    assistant.addMappedStatement(id, sqlSource, statementType, sqlCommandType, fetchSize, timeout, parameterMap, parameterTypeClass, resultMap, resultTypeClass, resultSetTypeEnum,
        flushCache, useCache, false,
        keyGenerator, keyProperty, keyColumn, null, languageDriver, null);

    id = assistant.applyCurrentNamespace(id, false);

    MappedStatement keyStatement = configuration.getMappedStatement(id, false);
    SelectKeyGenerator answer = new SelectKeyGenerator(keyStatement, executeBefore);
    configuration.addKeyGenerator(id, answer);
    return answer;
  }

}
