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
package org.apache.ibatis.builder.xml;

import java.util.List;
import java.util.Locale;

import org.apache.ibatis.builder.BaseBuilder;
import org.apache.ibatis.builder.MapperBuilderAssistant;
import org.apache.ibatis.executor.keygen.Jdbc3KeyGenerator;
import org.apache.ibatis.executor.keygen.KeyGenerator;
import org.apache.ibatis.executor.keygen.NoKeyGenerator;
import org.apache.ibatis.executor.keygen.SelectKeyGenerator;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.ResultSetType;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.mapping.StatementType;
import org.apache.ibatis.parsing.XNode;
import org.apache.ibatis.scripting.LanguageDriver;
import org.apache.ibatis.session.Configuration;

/**
 * sql语句构建器
 * @author Clinton Begin
 */
public class XMLStatementBuilder extends BaseBuilder {
  /**
   * 映射构建器助手
   */
  private MapperBuilderAssistant builderAssistant;
  /**
   * 当前(select|insert|update|delete)语句
   */
  private XNode context;
  /**
   * configuration中配置的数据库ID
   */
  private String requiredDatabaseId;

  public XMLStatementBuilder(Configuration configuration, MapperBuilderAssistant builderAssistant, XNode context) {
    this(configuration, builderAssistant, context, null);
  }

  public XMLStatementBuilder(Configuration configuration, MapperBuilderAssistant builderAssistant, XNode context, String databaseId) {
    super(configuration);
    this.builderAssistant = builderAssistant;
    this.context = context;
    this.requiredDatabaseId = databaseId;
  }

  /**
   * 核心方法,解析语句(select|insert|update|delete)
   * <select id="selectPerson" parameterType="int" parameterMap="deprecated" resultType="hashMap" resultMap="personResultMap" flushCache="false" useCache="true" timeout="10000" fetchSize="256" statementType="PREPARED" resultSetType="FORWARD_ONLY">
   *   SELECT * FROM PERSON WHERE ID = #{id}
   * </select>
   *
   * @link "https://mybatis.org/mybatis-3/zh/sqlmap-xml.html#select
   */
  public void parseStatementNode() {
    // 1、获得sql语句的id标识
    String id = context.getStringAttribute("id");
    // 2、获得sql语句的databaseId,一般为null
    String databaseId = context.getStringAttribute("databaseId");
    // 3、如果databaseId与configuration中配置的数据库ID不匹配,退出解析
    if (!databaseIdMatchesCurrent(id, databaseId, this.requiredDatabaseId)) {
      return;
    }

    // 4、fetchSize,尝试让驱动程序每次批量返回的结果行数等于这个设置值
    Integer fetchSize = context.getIntAttribute("fetchSize");
    // 5、timeout,在抛出异常之前，驱动程序等待数据库返回请求结果的秒数
    Integer timeout = context.getIntAttribute("timeout");
    // 6、引用外部 parameterMap,已废弃
    String parameterMap = context.getStringAttribute("parameterMap");
    // 7、参数类型
    String parameterType = context.getStringAttribute("parameterType");
    Class<?> parameterTypeClass = resolveClass(parameterType);
    // 8、引用外部的 resultMap(高级功能)
    String resultMap = context.getStringAttribute("resultMap");
    // 9、结果类型
    String resultType = context.getStringAttribute("resultType");
    Class<?> resultTypeClass = resolveClass(resultType);
    // 10、脚本语言,mybatis3.2的新功能
    String lang = context.getStringAttribute("lang");
    // 11、得到语言驱动,默认为 XMLLanguageDriver
    LanguageDriver langDriver = getLanguageDriver(lang);
    // 12、结果集类型，FORWARD_ONLY|SCROLL_SENSITIVE|SCROLL_INSENSITIVE ,默认为unset
    String resultSetType = context.getStringAttribute("resultSetType");
    ResultSetType resultSetTypeEnum = resolveResultSetType(resultSetType);
    // 13、语句类型, STATEMENT|PREPARED|CALLABLE 的一种，,默认为prepared预处理语句
    StatementType statementType = StatementType.valueOf(context.getStringAttribute("statementType", StatementType.PREPARED.toString()));
    // 14、获取命令类型(select|insert|update|delete)
    String nodeName = context.getNode().getNodeName();
    SqlCommandType sqlCommandType = SqlCommandType.valueOf(nodeName.toUpperCase(Locale.ENGLISH));
    // 15、是否为查询语句
    boolean isSelect = sqlCommandType == SqlCommandType.SELECT;
    // 16、flushCache,将其设置为 true后,只要语句被调用,都会导致本地缓存和二级缓存被清空。如果是查询语句,则默认为false,如果是其他语句，则默认为true
    boolean flushCache = context.getBooleanAttribute("flushCache", !isSelect);
    // 17、是否要缓存select结果,如果是查询语句默认为true
    boolean useCache = context.getBooleanAttribute("useCache", isSelect);
    // 18、个人理解resultOrdered为true就自动分组,"https://blog.csdn.net/weixin_40240756/article/details/108889127
    boolean resultOrdered = context.getBooleanAttribute("resultOrdered", false);
    // 19、解析<include>SQL片段
    XMLIncludeTransformer includeParser = new XMLIncludeTransformer(configuration, builderAssistant);
    includeParser.applyIncludes(context.getNode());
    // 20、解析<selectKey>,若存在,则将其解析成key映射语句存储到configuration中
    processSelectKeyNodes(id, parameterTypeClass, langDriver);
    // 21、将sql解析SqlSource,此时已经将sql片段拼接进去了（一般是DynamicSqlSource)
    SqlSource sqlSource = langDriver.createSqlSource(configuration, context, parameterTypeClass);
    //
    String resultSets = context.getStringAttribute("resultSets");
    //(仅对 insert 有用) 标记一个属性, MyBatis 会通过 getGeneratedKeys 或者通过 insert 语句的 selectKey 子元素设置它的值
    String keyProperty = context.getStringAttribute("keyProperty");
    //(仅对 insert 有用) 标记一个属性, MyBatis 会通过 getGeneratedKeys 或者通过 insert 语句的 selectKey 子元素设置它的值
    String keyColumn = context.getStringAttribute("keyColumn");
    KeyGenerator keyGenerator;
    String keyStatementId = id + SelectKeyGenerator.SELECT_KEY_SUFFIX;
    keyStatementId = builderAssistant.applyCurrentNamespace(keyStatementId, true);
    if (configuration.hasKeyGenerator(keyStatementId)) {
      keyGenerator = configuration.getKeyGenerator(keyStatementId);
    } else {
      keyGenerator = context.getBooleanAttribute("useGeneratedKeys",
          configuration.isUseGeneratedKeys() && SqlCommandType.INSERT.equals(sqlCommandType))
          ? new Jdbc3KeyGenerator() : new NoKeyGenerator();
    }

	//又去调助手类
    builderAssistant.addMappedStatement(id, sqlSource, statementType, sqlCommandType,
        fetchSize, timeout, parameterMap, parameterTypeClass, resultMap, resultTypeClass,
        resultSetTypeEnum, flushCache, useCache, resultOrdered,
        keyGenerator, keyProperty, keyColumn, databaseId, langDriver, resultSets);
  }

  /**
   * 20.1、解析<selectKey>
   *
   * 1、对于不支持自动生成主键列的数据库和可能不支持自动生成主键的 JDBC 驱动，MyBatis 有另外一种方法来生成主键
   * 2、可以获取insert后的主键ID
   *
   * e.q.
   * <insert id="insertAuthor">
   *   <selectKey keyProperty="id" resultType="int" order="BEFORE" databaseId="" keyColumn="" statementType="">
   *     select CAST(RANDOM()*1000000 as INTEGER) a from SYSIBM.SYSDUMMY1
   *   </selectKey>
   *   insert into Author
   *     (id, username, password, email,bio, favourite_section)
   *   values
   *     (#{id}, #{username}, #{password}, #{email}, #{bio}, #{favouriteSection,jdbcType=VARCHAR})
   * </insert>
   *  在上面的示例中，首先会运行 selectKey 元素中的语句，并设置 Author 的 id，然后才会调用插入语句。这样就实现了数据库自动生成主键类似的行为。
   *
   * @param id sql语句的id标识
   * @param parameterTypeClass 参数类型
   * @param langDriver 语言驱动
   * @link "https://mybatis.org/mybatis-3/zh/sqlmap-xml.html#insert_update_and_delete
   * @use "https://blog.csdn.net/xueguchen/article/details/108703837
   */
  private void processSelectKeyNodes(String id, Class<?> parameterTypeClass, LanguageDriver langDriver) {
    // 1、获得当前sql语句下所有的<selectKey>
    List<XNode> selectKeyNodes = context.evalNodes("selectKey");
    if (configuration.getDatabaseId() != null) {
      //  2、configuration配置了DatabaseId
      parseSelectKeyNodes(id, selectKeyNodes, parameterTypeClass, langDriver, configuration.getDatabaseId());
    }
    // 3、再执行一次，意思是只要写了该语句,不管configuration是否配置DatabaseId，都会解析
    parseSelectKeyNodes(id, selectKeyNodes, parameterTypeClass, langDriver, null);
    // 3、删除<select>下的<SelectKey>节点
    removeSelectKeyNodes(selectKeyNodes);
  }

  /**
   * 20.2、解析<selectKey>节点
   * @param parentId 当前sql语句的id标识
   * @param list  当前sql语句下所有的<selectKey>
   * @param parameterTypeClass 参数类型
   * @param langDriver 语言驱动
   * @param skRequiredDatabaseId  configuration配置的DatabaseId
   */
  private void parseSelectKeyNodes(String parentId, List<XNode> list, Class<?> parameterTypeClass, LanguageDriver langDriver, String skRequiredDatabaseId) {
    // 循环遍历当前sql语句下所有的<selectKey>
    for (XNode nodeToHandle : list) {
      // 1、当前sql语句的id标识+=键值生成器前缀
      String id = parentId + SelectKeyGenerator.SELECT_KEY_SUFFIX;
      // 2、获得当前<selectKey>的databaseId属性
      String databaseId = nodeToHandle.getStringAttribute("databaseId");
      if (databaseIdMatchesCurrent(id, databaseId, skRequiredDatabaseId)) {
        // 3、真正解析
        parseSelectKeyNode(id, nodeToHandle, parameterTypeClass, langDriver, databaseId);
      }
    }
  }

  /**
   * 20.3、解析<selectKey>节点
   *  <insert id="insertAuthor">
   *       <selectKey keyProperty="id" resultType="int" order="BEFORE" databaseId="" keyColumn="" statementType="">
   *         select CAST(RANDOM()*1000000 as INTEGER) a from SYSIBM.SYSDUMMY1
   *       </selectKey>
   *       insert into Author
   *         (id, username, password, email,bio, favourite_section)
   *       values
   *         (#{id}, #{username}, #{password}, #{email}, #{bio}, #{favouriteSection,jdbcType=VARCHAR})
   *   </insert>
   * @param id 当前sql语句的id标识+=键值生成器前缀
   * @param nodeToHandle  当前<selectKey>节点
   * @param parameterTypeClass 参数类型
   * @param langDriver 语言驱动
   * @param databaseId  当前<selectKey>的databaseId属性
   */
  private void parseSelectKeyNode(String id, XNode nodeToHandle, Class<?> parameterTypeClass, LanguageDriver langDriver, String databaseId) {
    // 1、获得selectKey的结果类型
    String resultType = nodeToHandle.getStringAttribute("resultType");
    Class<?> resultTypeClass = resolveClass(resultType);
    // 2、获得selectKey的语句类型，默认为预处理语句
    StatementType statementType = StatementType.valueOf(nodeToHandle.getStringAttribute("statementType", StatementType.PREPARED.toString()));
    // 3、获取keyProperty,结果应该被设置到的目标属性（通常是id）
    String keyProperty = nodeToHandle.getStringAttribute("keyProperty");
    // 4、获取keyColumn,结果集中生成列属性的列名
    String keyColumn = nodeToHandle.getStringAttribute("keyColumn");
    // 5、获取order,可以设置为 BEFORE 或 AFTER
    // 如果设置为 BEFORE，那么它首先会生成主键，设置 keyProperty 再执行插入语句。
    // 如果设置为 AFTER，那么先执行插入语句，然后是 selectKey 中的语句 - 这和 Oracle 数据库的行为相似
    boolean executeBefore = "BEFORE".equals(nodeToHandle.getStringAttribute("order", "AFTER"));

    // 6、不使用键值生成器
    KeyGenerator keyGenerator = new NoKeyGenerator();
    // 7、创建SqlSource
    SqlSource sqlSource = langDriver.createSqlSource(configuration, nodeToHandle, parameterTypeClass);
    SqlCommandType sqlCommandType = SqlCommandType.SELECT;
    // 8、构建映射语句,并将其添加到configuration
    builderAssistant.addMappedStatement(id, sqlSource, statementType, sqlCommandType, null, null, null, parameterTypeClass, null, resultTypeClass, null, false, false, false, keyGenerator, keyProperty, keyColumn, databaseId, langDriver, null);
    // 9、给id加上命名空间前缀
    id = builderAssistant.applyCurrentNamespace(id, false);
    // 10、根据id从configuration里拿到构建好的key映射语句
    MappedStatement keyStatement = configuration.getMappedStatement(id, false);
    // 11、将这条key映射语句包装下添加到configuration的KeyGenerator容器中
    configuration.addKeyGenerator(id, new SelectKeyGenerator(keyStatement, executeBefore));
  }

  /**
   * 20.3、删除<selectKey>节点
   */
  private void removeSelectKeyNodes(List<XNode> selectKeyNodes) {
    for (XNode nodeToHandle : selectKeyNodes) {
      nodeToHandle.getParent().getNode().removeChild(nodeToHandle.getNode());
    }
  }

  /**
   * 判断configuration中配置的databaseId与当前sql语句的databaseId是否匹配
   * @param id  当前sql语句的唯一标识
   * @param databaseId  当前sql语句的databaseId
   * @param requiredDatabaseId configuration中配置的databaseId
   */
  private boolean databaseIdMatchesCurrent(String id, String databaseId, String requiredDatabaseId) {
    if (requiredDatabaseId != null) {
      // 1、如果configuration中配置了数据库ID,则比较是否一致，一致则返回true,不一致返回false
      return requiredDatabaseId.equals(databaseId);
    }
    // 2、如果configuration中没配置数据库ID,此时sql语句配置了，那直接返回false
    if (databaseId != null) {
      return false;
    }
    // 3、如果configuration和当前sql语句都没配置数据库ID,且configuration里之前也没出现过同名sql语句,则直接返回true
    id = builderAssistant.applyCurrentNamespace(id, false);
    if (!this.configuration.hasStatement(id, false)) {
      return true;
    }
    // 4、如果configuration和当前sql语句都没配置数据库ID，但是之前出现过同名sql,如果同名sql也没配置databaseId则返回true,如果同名sql配置了，则返回false (这个判断是多余的，因为不允许出现同名sql)
    MappedStatement previous = this.configuration.getMappedStatement(id, false);
    return previous.getDatabaseId() == null;
  }

  /**
   * 取得语言驱动,默认为 XMLLanguageDriver
   * @param lang 驱动名
   */
  private LanguageDriver getLanguageDriver(String lang) {
    Class<?> langClass = null;
    if (lang != null) {
      langClass = resolveClass(lang);
    }
    //调用builderAssistant
    return builderAssistant.getLanguageDriver(langClass);
  }

}
