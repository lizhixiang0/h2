package com.zx.arch.xml;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description   Dome4j看名字就知道是采用的dom树方式解析配置文件
 * @blog "https://blog.csdn.net/ThinkWon/article/details/100642425?ops_request_misc=%25257B%252522request%25255Fid%252522%25253A%252522160930162116780257492266%252522%25252C%252522scm%252522%25253A%25252220140713.130102334.pc%25255Fblog.%252522%25257D&request_id=160930162116780257492266&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_v2~rank_v29-1-100642425.pc_v2_rank_blog_default&utm_term=xml
 * @note
 *               DOM：要求解析器把整个XML文档装载到内存，并解析成一个Document对象。
 *                  (a) 优点：元素与元素之间保留结构关系，故可以进行增删改查操作。
 *                  (b) 缺点：XML文档过大，可能出现内存溢出显现。
 *               SAX：是一种速度更快，更有效的方法。它逐行扫描文档，一边扫描一边解析。并以事件驱动的方式进行具体解析，每执行一行，都将触发对应的事件。（了解）
 *                  (a) 优点：处理速度快，可以处理大文件
 *                  (b) 缺点：只能读，逐行后将释放资源。
 **/
public class Dome4jTest {
    public static void main(String[] args) throws DocumentException {
        // 1 创建核心对象（new 方式）
        SAXReader saxReader = new SAXReader();
        //2 加载xml文档 获得dom树（核心对象调用read读取xml文件）
        Document doc = saxReader.read("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\demo.xml");
        //3 获得根元素（文档对象下面就是根元素）
        Element root = doc.getRootElement();
        //4 获得子元素（根节点下所有子元素）
        List<Element> list = root.elements();

        for (Element e : list) {
            // elementText("标签名") 获得指定名称元素的文本值 （指定标签的文本值）
            // getName() 获得当前元素名
            if ("TT".equals(e.getName())) {
                System.out.println(e.elementText("tt"));
                System.out.println(e.getName());
            }

        }

        //5、dom4j也可以结合XPath来快速解析xml  "https://www.cnblogs.com/vastsum/p/5940235.html
    }
}
