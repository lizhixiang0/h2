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
package org.apache.ibatis.scripting.xmltags;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.builder.BaseBuilder;
import org.apache.ibatis.builder.BuilderException;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.parsing.XNode;
import org.apache.ibatis.scripting.defaults.RawSqlSource;
import org.apache.ibatis.session.Configuration;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * XML脚本构建器,创建SqlSource
 * @author Clinton Begin
 */
public class XMLScriptBuilder extends BaseBuilder {
  /**
   * sql语句节点
   */
  private XNode context;

  /**
   * 参数类型
   */
  private Class<?> parameterType;
  /**
   * 判断是否是动态sql
   */
  private boolean isDynamic;

  public XMLScriptBuilder(Configuration configuration, XNode context) {
    this(configuration, context, null);
  }

  public XMLScriptBuilder(Configuration configuration, XNode context, Class<?> parameterType) {
    super(configuration);
    this.context = context;
    this.parameterType = parameterType;
  }

  /**
   * 核心方法,构建SqlSource
   * @return SqlSource
   */
  public SqlSource parseScriptNode() {
    // 1、解析动态标记
    List<SqlNode> contents = parseDynamicTags(context);
    MixedSqlNode rootSqlNode = new MixedSqlNode(contents);
    SqlSource sqlSource = null;
    if (isDynamic) {
      sqlSource = new DynamicSqlSource(configuration, rootSqlNode);
    } else {
      sqlSource = new RawSqlSource(configuration, rootSqlNode, parameterType);
    }
    return sqlSource;
  }

  /**
   * 解析动态标记
   * e.q.1
   *        DELETE FROM CODE
   * 		WHERE market_id = #{marketId}
   * 		AND id IN
   * 		<foreach collection="ids" index="index" item="value" open="(" separator="," close=")">
   * 			#{value}
   * 		</foreach>
   * 		OR parent_id IN
   * 		<foreach collection="ids" index="index" item="value" open="(" separator="," close=")">
   * 			#{value}
   * 		</foreach>
   *
   * e.q.2
   *        DELETE FROM CODE
   * 		<where>
   * 			type = #{type}
   * 			AND market_id = #{marketId}
   * 		</where>
   *
   * e.q.3
   *      	SELECT
   * 		 ...
   * 		FROM CODE a
   * 		 ...
   * 		WHERE a.del_flag = 0
   * 		<if test="type != null and type != ''">
   * 			AND a.type = #{type}
   * 		</if>
   *          ...
   *        <choose>
   *            <when test="type != null and type != '' and type == 'country'">
   *                ORDER BY a.label ASC
   *            </when>
   *            <otherwise>
   *                ORDER BY a.type, a.sort, child.sort, a.updated_date DESC
   *            </otherwise>
   *        </choose>
   *
   * @param node  sql语句节点
   * @return List<SqlNode>
   * @link "https://mybatis.org/mybatis-3/zh/dynamic-sql.html
   */
  List<SqlNode> parseDynamicTags(XNode node) {
    // 1、创建SqlNode集合容器
    List<SqlNode> contents = new ArrayList<>();
    // 2、获取当前sql语句节点的所有子节点（包括文本、元素）
    NodeList children = node.getNode().getChildNodes();
    // 3、循环遍历
    for (int i = 0; i < children.getLength(); i++) {
      // a、将子元素用XNode包装起来
      XNode child = node.newXNode(children.item(i));
      // b、下面分两种情况讨论,第一种是当前子节点是文本节点或CDATA节点,第二种情况当前子元素为元素节点
      if (child.getNode().getNodeType() == Node.CDATA_SECTION_NODE || child.getNode().getNodeType() == Node.TEXT_NODE) {
        // b1、取出文本内容
        String data = child.getStringBody("");
        // b1、将文本内容用TextSqlNode包装起来
        TextSqlNode textSqlNode = new TextSqlNode(data);
        // b1、判断是否是动态的文本,
        // 如果是则将TextSqlNode添加进contents且isDynamic设置为true
        // 不是则将文本用StaticTextSqlNode包装起来添加进contents
        if (textSqlNode.isDynamic()) {
          contents.add(textSqlNode);
          isDynamic = true;
        } else {
          contents.add(new StaticTextSqlNode(data));
        }
      } else if (child.getNode().getNodeType() == Node.ELEMENT_NODE) {
        // b2、取出元素节点名  (出现元素节点代表肯定是动态sql了)
        String nodeName = child.getNode().getNodeName();
        // b3、根据节点名获取对应的动态节点处理器，拿不到直接报错
        NodeHandler handler = nodeHandlers(nodeName);
        if (handler == null) {
          throw new BuilderException("Unknown element <" + nodeName + "> in SQL statement.");
        }
        // b4、解析动态节点
        handler.handleNode(child, contents);
        // b5、isDynamic设置为true
        isDynamic = true;
      }
    }
    return contents;
  }

  /**
   * 根据动态节点名获取节点处理器
   * @param nodeName  动态节点名,如trim、where、set、foreach、if、choose、when、otherwise、bind
   * @return 动态节点处理器
   */
  private NodeHandler nodeHandlers(String nodeName) {
    // 1、先注册9个不同的处理器,这种方式不需要写大量的 switch 或 if
    Map<String, NodeHandler> map = new HashMap<>(9);
    map.put("trim", new TrimHandler());
    map.put("where", new WhereHandler());
    map.put("set", new SetHandler());
    map.put("foreach", new ForEachHandler());
    map.put("if", new IfHandler());
    map.put("choose", new ChooseHandler());
    map.put("when", new IfHandler());
    map.put("otherwise", new OtherwiseHandler());
    map.put("bind", new BindHandler());
    // 2、然后获取
    return map.get(nodeName);
  }

  /**
   * 内部接口：动态节点处理器
   */
  private interface NodeHandler {
    /**
     * 核心方法
     * @param nodeToHandle 动态节点，如trim、where、set、foreach、if、choose、when、otherwise、bind
     * @param targetContents  List<SqlNode>
     */
    void handleNode(XNode nodeToHandle, List<SqlNode> targetContents);
  }

  /**
   * if处理器
   * <select id="findActiveBlogWithTitleLike"
   *      resultType="Blog">
   *   SELECT * FROM BLOG
   *   WHERE state = ‘ACTIVE’
   *   <if test="title != null">
   *     AND title like #{title}
   *   </if>
   * </select>
   */
  private class IfHandler implements NodeHandler {
    public IfHandler() {}

    @Override
    public void handleNode(XNode nodeToHandle, List<SqlNode> targetContents) {
      // 1、调用parseDynamicTags获得<if>节点下的文本元素
      List<SqlNode> contents = parseDynamicTags(nodeToHandle);
      // 2、构建混合sql节点,他的作用是将其内部包含的sql节点都执行一遍apply
      MixedSqlNode mixedSqlNode = new MixedSqlNode(contents);
      // 3、获得test属性值
      String test = nodeToHandle.getStringAttribute("test");
      // 4、构建IfSqlNode
      IfSqlNode ifSqlNode = new IfSqlNode(mixedSqlNode, test);
      targetContents.add(ifSqlNode);
    }
  }

  /**
   * Trim处理器
   * @link "https://blog.csdn.net/wt_better/article/details/80992014
   */
  private class TrimHandler implements NodeHandler {
    public TrimHandler() {}

    @Override
    public void handleNode(XNode nodeToHandle, List<SqlNode> targetContents) {
      List<SqlNode> contents = parseDynamicTags(nodeToHandle);
      MixedSqlNode mixedSqlNode = new MixedSqlNode(contents);
      String prefix = nodeToHandle.getStringAttribute("prefix");
      String prefixOverrides = nodeToHandle.getStringAttribute("prefixOverrides");
      String suffix = nodeToHandle.getStringAttribute("suffix");
      String suffixOverrides = nodeToHandle.getStringAttribute("suffixOverrides");
      TrimSqlNode trim = new TrimSqlNode(configuration, mixedSqlNode, prefix, prefixOverrides, suffix, suffixOverrides);
      targetContents.add(trim);
    }
  }

  /**
   *
   * where 处理器
   *
   * <select id="findActiveBlogLike"
   *      resultType="Blog">
   *   SELECT * FROM BLOG
   *   <where>
   *     <if test="state != null">
   *          state = #{state}
   *     </if>
   *     <if test="title != null">
   *         AND title like #{title}
   *     </if>
   *     <if test="author != null and author.name != null">
   *         AND author_name like #{author.name}
   *     </if>
   *   </where>
   * </select>
   *
   * where处理器
   */
  private class WhereHandler implements NodeHandler {
    public WhereHandler() {}

    @Override
    public void handleNode(XNode nodeToHandle, List<SqlNode> targetContents) {
      List<SqlNode> contents = parseDynamicTags(nodeToHandle);
      MixedSqlNode mixedSqlNode = new MixedSqlNode(contents);
      WhereSqlNode where = new WhereSqlNode(configuration, mixedSqlNode);
      targetContents.add(where);
    }
  }

  /**
   * 绑定处理器
   */
  private static class BindHandler implements NodeHandler {
    public BindHandler() {}

    @Override
    public void handleNode(XNode nodeToHandle, List<SqlNode> targetContents) {
      final String name = nodeToHandle.getStringAttribute("name");
      final String expression = nodeToHandle.getStringAttribute("value");
      final VarDeclSqlNode node = new VarDeclSqlNode(name, expression);
      targetContents.add(node);
    }
  }



  /**
   * set处理器
   */
  private class SetHandler implements NodeHandler {
    public SetHandler() {}

    @Override
    public void handleNode(XNode nodeToHandle, List<SqlNode> targetContents) {
      List<SqlNode> contents = parseDynamicTags(nodeToHandle);
      MixedSqlNode mixedSqlNode = new MixedSqlNode(contents);
      SetSqlNode set = new SetSqlNode(configuration, mixedSqlNode);
      targetContents.add(set);
    }
  }

  /**
   * forEach处理器
   */
  private class ForEachHandler implements NodeHandler {
    public ForEachHandler() {}

    @Override
    public void handleNode(XNode nodeToHandle, List<SqlNode> targetContents) {
      List<SqlNode> contents = parseDynamicTags(nodeToHandle);
      MixedSqlNode mixedSqlNode = new MixedSqlNode(contents);
      String collection = nodeToHandle.getStringAttribute("collection");
      String item = nodeToHandle.getStringAttribute("item");
      String index = nodeToHandle.getStringAttribute("index");
      String open = nodeToHandle.getStringAttribute("open");
      String close = nodeToHandle.getStringAttribute("close");
      String separator = nodeToHandle.getStringAttribute("separator");
      ForEachSqlNode forEachSqlNode = new ForEachSqlNode(configuration, mixedSqlNode, collection, index, item, open, close, separator);
      targetContents.add(forEachSqlNode);
    }
  }

  /**
   * otherwise处理器
   */
  private class OtherwiseHandler implements NodeHandler {
    public OtherwiseHandler() {}

    @Override
    public void handleNode(XNode nodeToHandle, List<SqlNode> targetContents) {
      List<SqlNode> contents = parseDynamicTags(nodeToHandle);
      MixedSqlNode mixedSqlNode = new MixedSqlNode(contents);
      targetContents.add(mixedSqlNode);
    }
  }

  /**
   * choose处理器
   */
  private class ChooseHandler implements NodeHandler {
    public ChooseHandler() {}

    @Override
    public void handleNode(XNode nodeToHandle, List<SqlNode> targetContents) {
      List<SqlNode> whenSqlNodes = new ArrayList<>();
      List<SqlNode> otherwiseSqlNodes = new ArrayList<>();
      handleWhenOtherwiseNodes(nodeToHandle, whenSqlNodes, otherwiseSqlNodes);
      SqlNode defaultSqlNode = getDefaultSqlNode(otherwiseSqlNodes);
      ChooseSqlNode chooseSqlNode = new ChooseSqlNode(whenSqlNodes, defaultSqlNode);
      targetContents.add(chooseSqlNode);
    }

    private void handleWhenOtherwiseNodes(XNode chooseSqlNode, List<SqlNode> ifSqlNodes, List<SqlNode> defaultSqlNodes) {
      List<XNode> children = chooseSqlNode.getChildren();
      for (XNode child : children) {
        String nodeName = child.getNode().getNodeName();
        NodeHandler handler = nodeHandlers(nodeName);
        if (handler instanceof IfHandler) {
          handler.handleNode(child, ifSqlNodes);
        } else if (handler instanceof OtherwiseHandler) {
          handler.handleNode(child, defaultSqlNodes);
        }
      }
    }

    private SqlNode getDefaultSqlNode(List<SqlNode> defaultSqlNodes) {
      SqlNode defaultSqlNode = null;
      if (defaultSqlNodes.size() == 1) {
        defaultSqlNode = defaultSqlNodes.get(0);
      } else if (defaultSqlNodes.size() > 1) {
        throw new BuilderException("Too many default (otherwise) elements in choose statement.");
      }
      return defaultSqlNode;
    }
  }

}
