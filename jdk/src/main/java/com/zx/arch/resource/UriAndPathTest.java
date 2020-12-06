package com.zx.arch.resource;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;

import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @author lizx
 * @since 1.0.0
 * @description
 *                  1、通常URL和URI的区别："https://www.cnblogs.com/hust-ghtao/p/4724885.html
 *                      只要能唯一标识资源的就是URI，在URI的基础上给出其资源的访问方式的就是URL
 *
 *                  2、测试Java中url 、uri 以及Path 的区别
 *
 *                          比较ok:"https://blog.csdn.net/abcwywht/article/details/53691632?utm_medium=distribute.pc_relevant.none-task-blog-BlogCommendFromBaidu-2.control&depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromBaidu-2.control
 *
 *                          url ：泛称统一资源定位符，一种定位资源的主要访问机制的字符串(通俗来讲。这里url是一个具体的地址。)，一个标准的URL必须包括：protocol、host、port、path、parameter、anchor。
 *                                java中的URl提供了解析URL的功能，可以将URL解析成一个结构化的数据，并提供了简单的查找主机和打开到指定资源的连接之类的网络 I/O 操作
 *                                @blog "https://blog.csdn.net/koflance/article/details/79635240
 *
 *                          uri ：泛意上 URI 是一种语义上的抽象概念，可以是绝对的，也可以是相对的，而URL则必须提供足够的信息来定位，是绝对的！
 *                                在Java类库中，URI类不包含任何访问资源的方法，它唯一的作用就是解析，解析标识符并将它们分解成各个不同的组成部分！
 *                                并且处理绝对标识符和相对标识符!
 *
 *                                URL 类的toURI() 和 URI.toURL() 可以实现这两个类之间的转换。
 *
 *                           Path：Jdk1.7 引入,我个人觉得Path类就是为了处理本机文件。是为了取代老版的File类.
 *                                  概念：https://www.iteye.com/blog/aswater-623971
 *                                  如何取代：https://gquintana.github.io/2017/09/02/Java-File-vs-Path.html
 *
 *
 *                 3、测试"/" 和 "\"的区别
 *                              反斜杠\表示母文件夹与子文件夹的路径分隔符。所以Path是\
 *                              斜杠/则用来分隔网站的主机服务器等信息,所以URL和uri都是用的/
 *                    总结：反斜杠\和斜杠/的区别在于区别本地与非本地。
 *
 *                    补充：Unix使用斜杆/作为路径分隔符,而Windows由于使用斜杆/作为DOS命令提示符的参数标志了,为了不混淆，所以采用反斜杠\作为路径分隔符！
 *                         但是对于windows系统的本地文件路径，"/"也能找到文件,我个人怀疑这是经过了网络路径（以后去了解）
 *                         不过，网络文件路径则一定要使用斜杆/
 *
 *
 **/
public class UriAndPathTest {
    private static void a() throws URISyntaxException, UnsupportedEncodingException {
        URL url = UriAndPathTest.class.getResource("/static/test.txt");
        URI uri = url.toURI();
        String path = url.getPath();

        String path2 = path.substring(1);

        System.out.println("url:====== ======  "+url);
        System.out.println("uri:====== ======  "+uri);
        System.out.println("path:======   ======  "+path);
        System.out.println("path.substring(1):====== ======  "+path2);

        Path p1 = Paths.get(uri);//没问题
        //Path p2= Paths.get(path);//报错,Url直接get的path一点用都没有。
        Path p3= Paths.get(path2); //没问题

        System.out.println("Path:====== ======  "+p1);

    }


    /**
     *  URI 可以对组成字段进行转码，获取字段时自动解码
     *  但是URI不允许出现空格！出现空格就报错！需要把空格换成%20，这是为啥呢？？
     */
    public static void b() {
        try {
            String urlString = "http://192.168.21.77:8080/swp/mainPage?aa= 11&bb%3D22";
            URI uri = URI.create(urlString.replace(" ", "%20"));
            System.out.println(uri.getPath()); // 输出：/swp/mainPage
            System.out.println(uri.getQuery());// 解码，输出： aa=11&bb=22*/
            URL url2 = new URL(urlString);
            System.out.println(url2.getPath());// 输出：/swp/mainPage
            System.out.println(url2.getQuery());// 不解码，输出：aa=11&bb%3D22
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    /**
     * http请求，使用uri(资源的各种信息)获取资源
     */
    public static void c() throws IOException, URISyntaxException {
        URL url = new URL("https://imgm.gmw.cn/attachement/jpg/site215/20201119/4364645368520067749.jpg");
        HttpGet httpGet = new HttpGet(url.toURI());
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpResponse httpResponse = httpClient.execute(httpGet);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        httpResponse.getEntity().writeTo(output);
        System.out.println(new String(output.toByteArray()).length());
        httpGet.releaseConnection();
    }

    /**
     * URL类可以直接打开一个到达资源的流
     * @throws IOException
     */
    public static void d() throws IOException {
        URL url = new URL("https://imgm.gmw.cn/attachement/jpg/site215/20201119/4364645368520067749.jpg");
        URLConnection urlcon = url.openConnection();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len = -1;
        // 读取内容不含响应头
        while ((len = urlcon.getInputStream().read(buffer)) != -1)
        {
            output.write(buffer, 0, len);
        }
        System.out.println(new String(output.toByteArray()).length());

    }





        public static void main(String[] args) throws URISyntaxException, IOException {
        b();
    }
}

