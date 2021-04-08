/*
 * Copyright 2012 MyBatis.org.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ibatis.builder.xml;

import org.apache.ibatis.builder.IncompleteElementException;
import org.apache.ibatis.builder.MapperBuilderAssistant;
import org.apache.ibatis.parsing.PropertyParser;
import org.apache.ibatis.parsing.XNode;
import org.apache.ibatis.session.Configuration;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * XML <include>转换器
 *
 * e.q.
 *
 * 	<sql id="codeColumns">
 * 		a.id AS "id",
 * 		a.market_id AS "marketId",
 * 		a.type AS "type",
 * 	</sql>
 *
 * 	<sql id="codeJoins">
 * 		LEFT JOIN PAX_CODE parent ON a.parent_id = parent.id
 * 		LEFT JOIN PAX_CODE child ON a.id = child.parent_id
 * 	</sql>
 *
 * 	<select id="get" resultMap="codeResult">
 * 		SELECT
 * 		<include refid="codeColumns"/>
 * 		FROM PAX_CODE a
 * 		<include refid="codeJoins"/>
 * 		WHERE a.id = #{id} AND a.del_flag = '0'
 * 	</select>
 *
 * @author Frank D. Martinez [mnesarco]
 */
public class XMLIncludeTransformer {

  private final Configuration configuration;
  private final MapperBuilderAssistant builderAssistant;

  public XMLIncludeTransformer(Configuration configuration, MapperBuilderAssistant builderAssistant) {
    this.configuration = configuration;
    this.builderAssistant = builderAssistant;
  }

  /**
   * 核心方法
   *
   *  <sql id="codeColumns">
   *  	a.id AS "id",
   *  	a.market_id AS "marketId",
   *  	a.type AS "type",
   *  </sql>
   *
   * <select id="selectUsers" resultType="map">
   *   select <include refid="userColumns"/>
   *   from some_table
   *   where id = #{id}
   * </select>
   * @param source sql语句节点或者是<include>节点
   */
  public void applyIncludes(Node source) {
    // 4、然后走这,如果是<include>节点就往下走
    if ("include".equals(source.getNodeName())) {
      // a、拿到SQL片段节点
      Node toInclude = findSqlFragment(getStringAttribute(source, "refid"));
      // b、将SQL片段节点作为source,继续调用本方法,如果sql片段里面没用其他sql片段,那调不调用没区别（这里我假设每调用，先看懂代码）
      applyIncludes(toInclude);
      // c、下面就是将字符串拼接进来
      // c1、判断<include>节点和<sql>是否在同一个映射文件里,不在的话把<sql>节点加到<include>所在document（正常都在）
      if (toInclude.getOwnerDocument() != source.getOwnerDocument()) {
        toInclude = source.getOwnerDocument().importNode(toInclude, true);
      }
      // c2、拿到<include>的父节点(select或其他),然后用子节点sql替换其中的子节点<include>
      source.getParentNode().replaceChild(toInclude, source);
      // c3、使用while循环,将sql节点下的文本都insert到父节点(select或其他)
      while (toInclude.hasChildNodes()) {
        toInclude.getParentNode().insertBefore(toInclude.getFirstChild(), toInclude);
      }
      // c4、所有文本都添加到父节点(select或其他)后，删除<sql节点>
      toInclude.getParentNode().removeChild(toInclude);
    } else if (source.getNodeType() == Node.ELEMENT_NODE) {
      // 1、一开始会走这段，如果source是个节点,那就取得其所有子节点,如果不是,就结束了
      NodeList children = source.getChildNodes();
      // 2、遍历子节点
      for (int i=0; i<children.getLength(); i++) {
        // 3、递归调用本方法，传入子节点
        applyIncludes(children.item(i));
      }
    }
  }

  /**
   * 根据ID从configuration取sql片段
   * @param refid id
   * @return SqlFragment
   */
  private Node findSqlFragment(String refid) {
    refid = PropertyParser.parse(refid, configuration.getVariables());
    refid = builderAssistant.applyCurrentNamespace(refid, true);
    try {
      // 1、去之前存到内存map的SQL片段中寻找
      XNode nodeToInclude = configuration.getSqlFragments().get(refid);
      // 2、clone一下，以防改写
      return nodeToInclude.getNode().cloneNode(true);
    } catch (IllegalArgumentException e) {
      throw new IncompleteElementException("Could not find SQL statement to include with refid '" + refid + "'", e);
    }
  }

  private String getStringAttribute(Node node, String name) {
    return node.getAttributes().getNamedItem(name).getNodeValue();
  }
}
