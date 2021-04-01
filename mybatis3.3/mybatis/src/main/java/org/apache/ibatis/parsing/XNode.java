/*
 *    Copyright 2009-2011 the original author or authors.
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
package org.apache.ibatis.parsing;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.w3c.dom.CharacterData;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * 对org.w3c.dom.Node的包装
 * @author Clinton Begin
 */
public class XNode {

  private Node node;
  private String name;
  private String body;
  private Properties attributes;
  private Properties variables;
  private XPathParser xpathParser;

  /**
   * 在构造时就将元素的属性和文本解析好
   * @param xpathParser xpath解析器
   * @param node 当前元素
   * @param variables 配置文件参数值
   */
  public XNode(XPathParser xpathParser, Node node, Properties variables) {
    this.xpathParser = xpathParser;
    this.node = node;
    this.name = node.getNodeName();
    this.variables = variables;
    this.attributes = parseAttributes(node);
    this.body = parseBody(node);
  }

  /**
   * 构造XNode时调用,将当前元素的属性取出全部放到attributes中,且根据给定的variables,将${var}替换成具体属性值
   * @param n 当前元素
   * @return   元素的属性值
   */
  private Properties parseAttributes(Node n) {
    Properties attributes = new Properties();
    NamedNodeMap attributeNodes = n.getAttributes();
    if (attributeNodes != null) {
      for (int i = 0; i < attributeNodes.getLength(); i++) {
        Node attribute = attributeNodes.item(i);
        String value = PropertyParser.parse(attribute.getNodeValue(), variables);
        attributes.put(attribute.getNodeName(), value);
      }
    }
    return attributes;
  }

  private String parseBody(Node node) {
    //如果当前元素是文本元素,则直接取出文本内容
    String data = getBodyData(node);
    if (data == null) {
      // 当前元素不是文本元素则获取此元素下的文本元素
      NodeList children = node.getChildNodes();
      for (int i = 0; i < children.getLength(); i++) {
        Node child = children.item(i);
        data = getBodyData(child);
        //只要能获取到文本节点,立刻结束循环。此时body值是node的第一个文本节点的内容,(通常我们只会在一个元素节点中放置一个文本元素)
        if (data != null) {
          break;
        }
      }
    }
    return data;
  }

  private String getBodyData(Node child) {
    //如果该节点是文本节点或者CDATA节点，取其文本值
    if (child.getNodeType() == Node.CDATA_SECTION_NODE || child.getNodeType() == Node.TEXT_NODE) {
      String data = ((CharacterData) child).getData();
      data = PropertyParser.parse(data, variables);
      return data;
    }
    return null;
  }

  /**
   * 获取所有子元素节点的属性名和属性值
   * @return Properties
   */
  public Properties getChildrenAsProperties() {
    Properties properties = new Properties();
    for (XNode child : getChildren()) {
      String name = child.getStringAttribute("name");
      String value = child.getStringAttribute("value");
      if (name != null && value != null) {
        properties.setProperty(name, value);
      }
    }
    return properties;
  }

  /**
   * 获取子元素节点
   * @return 子元素节点集合
   */
  public List<XNode> getChildren() {
    List<XNode> children = new ArrayList<>();
    NodeList nodeList = node.getChildNodes();
    if (nodeList != null) {
      for (int i = 0, n = nodeList.getLength(); i < n; i++) {
        Node node = nodeList.item(i);
        if (node.getNodeType() == Node.ELEMENT_NODE) {
          children.add(new XNode(xpathParser, node, variables));
        }
      }
    }
    return children;
  }

  public XNode newXNode(Node node) {
    return new XNode(xpathParser, node, variables);
  }

  /**
   * 调用Node.getParentNode,取到则包装成XNode返回
   * @return XNode
   */
  public XNode getParent() {
    Node parent = node.getParentNode();
    if (!(parent instanceof Element)) {
      return null;
    } else {
      return new XNode(xpathParser, parent, variables);
    }
  }

  /**
   * @return 获取该元素节点的全路径
   * 补充: stringBuilder.insert(offset,str) ===>  就是在原序列的offset处插入字符str并生成新的StringBuilder对象。
   */
  public String getPath() {
    StringBuilder builder = new StringBuilder();
    Node current = node;
    while (current instanceof Element) {
      if (current != node) {
        builder.insert(0, "/");
      }
      builder.insert(0, current.getNodeName());
      current = current.getParentNode();
    }
    return builder.toString();
  }



  /**
   * 取得当前元素全路径各级元素节点的标识符   resultMap[authorResult]_result[username]
   * 	<resultMap id="authorResult" type="Author">
   * 	  <id property="id" column="author_id"/>
   * 	  <result property="username" column="author_username"/>
   * 	  <result property="password" column="author_password"/>
   * 	  <result property="email" column="author_email"/>
   * 	  <result property="bio" column="author_bio"/>
   * 	</resultMap>
   * @return 标示符
   */
  public String getValueBasedIdentifier() {
    StringBuilder builder = new StringBuilder();
    XNode current = this;
    while (current != null) {
      if (current != this) {
        builder.insert(0, "_");
      }
      //先拿id，拿不到再拿value,再拿不到拿property
      String value = current.getStringAttribute("id",current.getStringAttribute("value",current.getStringAttribute("property", null)));
      if (value != null) {
        value = value.replace('.', '_');
        builder.insert(0, "]");
        builder.insert(0,value);
        builder.insert(0, "[");
      }
      builder.insert(0, current.getName());
      current = current.getParent();
    }
    return builder.toString();
  }

  /**
   * 以下方法都是把XPathParser的方法再写了一遍,方便直接通过XNode来使用
   * @param expression
   * @return
   */
  public String evalString(String expression) {
    return xpathParser.evalString(node, expression);
  }

  public Boolean evalBoolean(String expression) {
    return xpathParser.evalBoolean(node, expression);
  }

  public Double evalDouble(String expression) {
    return xpathParser.evalDouble(node, expression);
  }

  public List<XNode> evalNodes(String expression) {
    return xpathParser.evalNodes(node, expression);
  }

  public XNode evalNode(String expression) {
    return xpathParser.evalNode(node, expression);
  }

  public Node getNode() {
    return node;
  }

  public String getName() {
    return name;
  }

  /**
   * 以下是一些getBody的方法
   * @return String
   */
  public String getStringBody() {
    return getStringBody(null);
  }

  public String getStringBody(String def) {
    if (body == null) {
      return def;
    } else {
      return body;
    }
  }

  public Boolean getBooleanBody() {
    return getBooleanBody(null);
  }

  public Boolean getBooleanBody(Boolean def) {
    if (body == null) {
      return def;
    } else {
      return Boolean.valueOf(body);
    }
  }

  public Integer getIntBody() {
    return getIntBody(null);
  }

  public Integer getIntBody(Integer def) {
    if (body == null) {
      return def;
    } else {
      return Integer.parseInt(body);
    }
  }

  public Long getLongBody() {
    return getLongBody(null);
  }

  public Long getLongBody(Long def) {
    if (body == null) {
      return def;
    } else {
      return Long.parseLong(body);
    }
  }

  public Double getDoubleBody() {
    return getDoubleBody(null);
  }

  public Double getDoubleBody(Double def) {
    if (body == null) {
      return def;
    } else {
      return Double.parseDouble(body);
    }
  }

  public Float getFloatBody() {
    return getFloatBody(null);
  }

  public Float getFloatBody(Float def) {
    if (body == null) {
      return def;
    } else {
      return Float.parseFloat(body);
    }
  }

  /**
   * 以下是一些getAttribute的方法
   * @param enumType
   * @param name
   * @param <T>
   * @return
   */
  public <T extends Enum<T>> T getEnumAttribute(Class<T> enumType, String name) {
    return getEnumAttribute(enumType, name, null);
  }

  public <T extends Enum<T>> T getEnumAttribute(Class<T> enumType, String name, T def) {
    String value = getStringAttribute(name);
    if (value == null) {
      return def;
    } else {
      return Enum.valueOf(enumType, value);
    }
  }

  /**
   *
   * 在当前节点体内（注意不是元素体下），根据属性名获取属性值，例如 <property name="username" value="dev_user"/>
   * @param name username
   * @return dev_user
   */
  public String getStringAttribute(String name) {
    return getStringAttribute(name, null);
  }

  public String getStringAttribute(String name, String def) {
    String value = attributes.getProperty(name);
    if (value == null) {
      return def;
    } else {
      return value;
    }
  }

  public Boolean getBooleanAttribute(String name) {
    return getBooleanAttribute(name, null);
  }

  public Boolean getBooleanAttribute(String name, Boolean def) {
    String value = attributes.getProperty(name);
    if (value == null) {
      return def;
    } else {
      return Boolean.valueOf(value);
    }
  }

  public Integer getIntAttribute(String name) {
    return getIntAttribute(name, null);
  }

  public Integer getIntAttribute(String name, Integer def) {
    String value = attributes.getProperty(name);
    if (value == null) {
      return def;
    } else {
      return Integer.parseInt(value);
    }
  }

  public Long getLongAttribute(String name) {
    return getLongAttribute(name, null);
  }

  public Long getLongAttribute(String name, Long def) {
    String value = attributes.getProperty(name);
    if (value == null) {
      return def;
    } else {
      return Long.parseLong(value);
    }
  }

  public Double getDoubleAttribute(String name) {
    return getDoubleAttribute(name, null);
  }

  public Double getDoubleAttribute(String name, Double def) {
    String value = attributes.getProperty(name);
    if (value == null) {
      return def;
    } else {
      return Double.parseDouble(value);
    }
  }

  public Float getFloatAttribute(String name) {
    return getFloatAttribute(name, null);
  }

  public Float getFloatAttribute(String name, Float def) {
    String value = attributes.getProperty(name);
    if (value == null) {
      return def;
    } else {
      return Float.parseFloat(value);
    }
  }




  /**
   * 打印当前节点的信息
   * @return String
   */
  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("<");
    builder.append(name);
    for (Map.Entry<Object, Object> entry : attributes.entrySet()) {
      builder.append(" ");
      builder.append(entry.getKey());
      builder.append("=\"");
      builder.append(entry.getValue());
      builder.append("\"");
    }
    List<XNode> children = getChildren();
    if (!children.isEmpty()) {
      builder.append(">\n");
      for (XNode node : children) {
        //递归取得孩子的toString
        builder.append(node.toString());
      }
      builder.append("</");
      builder.append(name);
      builder.append(">");
    } else if (body != null) {
      builder.append(">");
      builder.append(body);
      builder.append("</");
      builder.append(name);
      builder.append(">");
    } else {
      builder.append("/>");
    }
    builder.append("\n");
    return builder.toString();
  }

}