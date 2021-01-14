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
package org.apache.ibatis.parsing;

import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.ibatis.builder.BuilderException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * @author Clinton Begin
 * mybatis自己使用的XPath解析器，里面主要是两个功能:
 *                                 1、根据xml配置文件生成document！
 *                                 2、根据不同的expression和returnType来使用xpath.evaluate(expression, document, returnType)实现对XML文档的解析!
 *
 */
public class XPathParser {

  private Document document;
  private boolean validation;
  private EntityResolver entityResolver;
  private Properties variables;
  private XPath xpath;

  /**
   * 1~4,validation默认为false ,不使用DTD文件验证XML是否合法
   *
   * @param xml
   * @note 一些构造函数,全部调用commonConstructor以及createDocument
   *      可以学学这种方式！！将构造document对象和XPath对象分成了两步！
   *        第一步调用commonConstructor（validation,variables,entityResolver),传递一些配置参数，并构造Xpath对象
   *        第二步调用createDocument（inputSource）,将数据源传递过去，构造document对象
   */
  public XPathParser(String xml) {
    commonConstructor(false, null, null);
    this.document = createDocument(new InputSource(new StringReader(xml)));
  }

  public XPathParser(Reader reader) {
    commonConstructor(false, null, null);
    this.document = createDocument(new InputSource(reader));
  }

  public XPathParser(InputStream inputStream) {
    commonConstructor(false, null, null);
    this.document = createDocument(new InputSource(inputStream));
  }

  public XPathParser(Document document) {
    commonConstructor(false, null, null);
    this.document = document;
  }

  /**
   * 5~8,validation默认为true ,使用DTD文件验证XML是否合法,但是不使用本地的DTD文件
   * @param xml
   * @param validation
   */
  public XPathParser(String xml, boolean validation) {
    commonConstructor(validation, null, null);
    this.document = createDocument(new InputSource(new StringReader(xml)));
  }

  public XPathParser(Reader reader, boolean validation) {
    commonConstructor(validation, null, null);
    this.document = createDocument(new InputSource(reader));
  }

  public XPathParser(InputStream inputStream, boolean validation) {
    commonConstructor(validation, null, null);
    this.document = createDocument(new InputSource(inputStream));
  }

  public XPathParser(Document document, boolean validation) {
    commonConstructor(validation, null, null);
    this.document = document;
  }

  /**
   * 9~12,validation默认为true ,使用DTD文件验证XML是否合法,但是不使用本地的DTD文件,同时传入参数Properties
   * @param xml
   * @param validation
   * @param variables
   */
  public XPathParser(String xml, boolean validation, Properties variables) {
    commonConstructor(validation, variables, null);
    this.document = createDocument(new InputSource(new StringReader(xml)));
  }

  public XPathParser(Reader reader, boolean validation, Properties variables) {
    commonConstructor(validation, variables, null);
    this.document = createDocument(new InputSource(reader));
  }

  public XPathParser(InputStream inputStream, boolean validation, Properties variables) {
    commonConstructor(validation, variables, null);
    this.document = createDocument(new InputSource(inputStream));
  }

  public XPathParser(Document document, boolean validation, Properties variables) {
    commonConstructor(validation, variables, null);
    this.document = document;
  }

  /**
   * 13~16,validation默认为true ,使用DTD文件验证XML是否合法,使用本地的DTD文件,同时传入参数Properties
   * @param xml
   * @param validation
   * @param variables
   * @param entityResolver
   */
  public XPathParser(String xml, boolean validation, Properties variables, EntityResolver entityResolver) {
    commonConstructor(validation, variables, entityResolver);
    this.document = createDocument(new InputSource(new StringReader(xml)));
  }

  public XPathParser(Reader reader, boolean validation, Properties variables, EntityResolver entityResolver) {
    commonConstructor(validation, variables, entityResolver);
    this.document = createDocument(new InputSource(reader));
  }

  public XPathParser(InputStream inputStream, boolean validation, Properties variables, EntityResolver entityResolver) {
    commonConstructor(validation, variables, entityResolver);
    this.document = createDocument(new InputSource(inputStream));
  }

  public XPathParser(Document document, boolean validation, Properties variables, EntityResolver entityResolver) {
    commonConstructor(validation, variables, entityResolver);
    this.document = document;
  }

  /**
   * 17.允许单独设置Properties
   * @param variables
   */
  public void setVariables(Properties variables) {
    this.variables = variables;
  }


  /**
   * 根据给定的表达式expression来获得xml文件里表达式对应的元素值
   * @param expression
   * @return
   */
  public String evalString(String expression) {
    return evalString(document, expression);
  }


  /**
   * 先用xpath解析获得元素内容（value）, 然后再调用PropertyParser去处理内容
   *      <property name="driver" value="${driver}" />    <<<<=====================>>> driver=com.mysql.jdbc.Driver
   * @param root
   * @param expression
   * @return
   */
  public String evalString(Object root, String expression) {
    String result = (String) evaluate(expression, root, XPathConstants.STRING);
    result = PropertyParser.parse(result, variables);
    return result;
  }

  public Boolean evalBoolean(String expression) {
    return evalBoolean(document, expression);
  }

  public Boolean evalBoolean(Object root, String expression) {
    return (Boolean) evaluate(expression, root, XPathConstants.BOOLEAN);
  }

  public Short evalShort(String expression) {
    return evalShort(document, expression);
  }

  public Short evalShort(Object root, String expression) {
    return Short.valueOf(evalString(root, expression));
  }

  public Integer evalInteger(String expression) {
    return evalInteger(document, expression);
  }

  public Integer evalInteger(Object root, String expression) {
    return Integer.valueOf(evalString(root, expression));
  }

  public Long evalLong(String expression) {
    return evalLong(document, expression);
  }

  public Long evalLong(Object root, String expression) {
    return Long.valueOf(evalString(root, expression));
  }

  public Float evalFloat(String expression) {
    return evalFloat(document, expression);
  }

  public Float evalFloat(Object root, String expression) {
    return Float.valueOf(evalString(root, expression));
  }

  public Double evalDouble(String expression) {
    return evalDouble(document, expression);
  }

  public Double evalDouble(Object root, String expression) {
    return (Double) evaluate(expression, root, XPathConstants.NUMBER);
  }

  public List<XNode> evalNodes(String expression) {
    return evalNodes(document, expression);
  }

  public List<XNode> evalNodes(Object root, String expression) {
    List<XNode> xnodes = new ArrayList<XNode>();
    NodeList nodes = (NodeList) evaluate(expression, root, XPathConstants.NODESET);
    for (int i = 0; i < nodes.getLength(); i++) {
      xnodes.add(new XNode(this, nodes.item(i), variables));
    }
    return xnodes;
  }

  public XNode evalNode(String expression) {
    return evalNode(document, expression);
  }

  public XNode evalNode(Object root, String expression) {
    Node node = (Node) evaluate(expression, root, XPathConstants.NODE);
    if (node == null) {
      return null;
    }
    return new XNode(this, node, variables);
  }

  /**
   * 最终全部合流到这儿，调用XPath.evaluate,根据表达式和返回类型对document进行解析并返回结果
   * @param expression
   * @param root
   * @param returnType
   * @return
   */
  private Object evaluate(String expression, Object root, QName returnType) {
    try {
      return xpath.evaluate(expression, root, returnType);
    } catch (Exception e) {
      throw new BuilderException("Error evaluating XPath.  Cause: " + e, e);
    }
  }

  private void commonConstructor(boolean validation, Properties variables, EntityResolver entityResolver) {
    this.validation = validation;
    this.entityResolver = entityResolver;
    this.variables = variables;
    //共通构造函数，除了把参数都设置到实例变量里面去以外，还初始化了XPath
    XPathFactory factory = XPathFactory.newInstance();
    this.xpath = factory.newXPath();
  }

  private Document createDocument(InputSource inputSource) {
    try {
      //这个是DOM解析方式
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      // 是否使用DTD文件验证XML是否合法
      // 注意，如果XML文档声明了一个DTD ，即使不启用校验（validation）这个特性，解析器也会读入这个DTD ,目的是保证XML文档中entity reference被正确的扩展，防止出现格式不正确的XML文档，只有在XML文档序言部分的声明中standalone属性被置为true时，外部的DTD才会被完全忽略掉。
      factory.setValidating(validation);
		//名称空间
      factory.setNamespaceAware(false);
		//忽略注释
      factory.setIgnoringComments(true);
		//忽略空白
      factory.setIgnoringElementContentWhitespace(false);
		//把 CDATA 节点转换为 Text 节点
      factory.setCoalescing(false);
		//扩展实体引用
      factory.setExpandEntityReferences(true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      // 用来定位DTD文件,在获取DTD文件的时候，根据映射关系，将远程的url转成本地的DTD文件路径
      builder.setEntityResolver(entityResolver);
      // 指定解析器要使用的ErrorHandler ,注意如果将其设置为null则导致使用其自身的默认实现和行为的基础实现
      builder.setErrorHandler(new ErrorHandler() {
        @Override
        public void error(SAXParseException exception) throws SAXException {
          throw exception;
        }

        @Override
        public void fatalError(SAXParseException exception) throws SAXException {
          throw exception;
        }

        @Override
        public void warning(SAXParseException exception) {
        }
      });
      /**
       * Parse the content of the given input source as an XML document
       * 将配置文件加载到一个Document对象中
       */
      return builder.parse(inputSource);
    } catch (Exception e) {
      throw new BuilderException("Error creating document instance.  Cause: " + e, e);
    }
  }



}
