package com.zx.arch.xml;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.FileInputStream;

/**
 * @author lizx
 * @since 1.0.0
 * @description  XPath 使用路径表达式来选取 XML 文档中的节点或节点集
 * @blog "https://blog.csdn.net/weixin_30293135/article/details/99792899
 **/
public class XpathTest {

    private static Document doc;

    private static XPath xpath;

    /**
     * 初始化Document、XPath对象
     * @throws Exception
     */
    public static void init() throws Exception {
        // 创建Document对象
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setValidating(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        doc = db.parse(new FileInputStream(new File("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\demo.xml")));

        // 创建XPath对象
        XPathFactory factory = XPathFactory.newInstance();
        xpath = factory.newXPath();
    }

    /**
     * Xpath的表达式多种多样,所以有多种用法：如下是一些例子
     *              1、获取根元素
     *              2、获取子元素并打印
     *              3、获取部分元素
     *              4、获取指定层级的元素
     *              5、获取指定属性的元素（例如获取所有大于指定价格的书箱）
     *              6、获得指定层级的元素文本
     *
     *
     */


    /**
     * 获取根元素
     *
     * @throws XPathExpressionException
     */
    public static void getRootEle() throws XPathExpressionException {
        Node node = (Node) xpath.evaluate("/*", doc, XPathConstants.NODE);
        System.out.println(node.getNodeName()+"\r\n");
    }
    /**
     * 获取指定层级的元素
     * @throws XPathExpressionException
     * //web-app/servlet/servlet-name/
     */
    public static void getLevelElements() throws XPathExpressionException {
        NodeList nodeList = (NodeList) xpath.evaluate("/web-app/servlet/*", doc,
                XPathConstants.NODESET);
        for (int i = 0; i < nodeList.getLength(); i++) {
            System.out.print(nodeList.item(i).getNodeName() + " = " + nodeList.item(i).getTextContent() + "\r\n");
        }
    }

    /**
     * 获取指定层级的元素文本
     * @throws XPathExpressionException
     * //web-app/servlet/servlet-name/
     */
    public static void getLevelElementsText() throws XPathExpressionException {
        String content = (String) xpath.evaluate("/web-app/servlet/servlet-name", doc,XPathConstants.STRING);
        System.out.println(content);
    }

    public static void main(String[] args) throws Exception {
        init();
        getRootEle();
        getLevelElements();
        getLevelElementsText();
    }
}
