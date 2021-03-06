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
package org.apache.ibatis.io;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;

/**
 * A default implementation of {@link VFS} that works for most application servers.
 * 默认的VFS，提供了读取jar包的方法
 *
 * @author Ben Gunter
 */
public class DefaultVFS extends VFS {
  private static final Log log = LogFactory.getLog(ResolverUtil.class);

  /**
   * 所有的jar文件 前四个字节都是 0x50 0x4b 0x03 0x04
   */
  private static final byte[] JAR_MAGIC = { 'P', 'K', 3, 4 };

  @Override
  public boolean isValid() {
    return true;
  }

  @Override
  public List<String> list(URL url, String path) throws IOException {
    InputStream is = null;
    try {
      List<String> resources = new ArrayList<>();
      // 1、首先，搞到JAR文件(包含所需资源)的URL
      URL jarUrl = findJarForResource(url);
      if (jarUrl != null) {
        // 这个注意下，jar包文件是不能直接通过File这种文件来读取的，得通过流，我写在这里的原因是，很多时候写代码时需要用到资源文件，此时不能直接使用File,
        // 生产环境打成jar包之后通过new File()是找不到的！得通过流，类似this.clazz.getResourceAsStream
        is = jarUrl.openStream();
        log.debug("Listing " + url);
        // 1.1 文件被找到，我们将,用JDK自带的JarInputStream来读取jar包,列出JAR中读取到的子资源。
        resources = listResources(new JarInputStream(is), path);
      }else {
        // 存储查出的子资源url
        List<String> children = new ArrayList<>();
        try {
          // 2、一些url可能会给出一个JAR流，但是其字符串内就是么得".jar"的字样，针对这种我们直接通过魔法数判断
          if (isJar(url)) {
            // 2.1 判断是jar包,打开字节流
            is = url.openStream();
            // 2.1.1 也是用JDK自带的JarInputStream来读取jar包
            JarInputStream jarInput = new JarInputStream(is);
            log.debug("Listing " + url);
            for (JarEntry entry; (entry = jarInput.getNextJarEntry()) != null;) {
              log.debug("Jar entry: " + entry.getName());
              // 2.1.2 把查出来的资源路径添加进children集合
              children.add(entry.getName());
            }
            // 2.1.3 关闭流
            jarInput.close();
          }else {
            // 2.2 判断不是jar包,有可能给的是文件目录
            //有些servlet容器允许从文件夹(文件夹本质上也是文本文件，它逐行列出子资源的文本名),但是我们么得办法去判断是不是
            //所以打开字节流,使用reader.readLine()去一行行读取，每读一行就是要类加载去加载对应的资源，只要报错了，就说明不是
            is = url.openStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            List<String> lines = new ArrayList<>();
            for (String line; (line = reader.readLine()) != null;) {
              log.debug("Reader entry: " + line);
              lines.add(line);
              if (getResources(path + "/" + line).isEmpty()) {
                // 2.2.1 只要有一行读不出来内容，就清空lines,然后跳出循环
                lines.clear();
                break;
              }
            }
            // 2.2.2 如果lines不为空，说明确实如我们所料，该项目是通过文本文件之类的东西逐行列出资源文件
            if (!lines.isEmpty()) {
              log.debug("Listing " + url);
              // 2.2.3 将lines中内容归并到children
              children.addAll(lines);
            }
          }
        } catch (FileNotFoundException e) {
          /*
           对于文件url, openStream()等调用可能会失败，可能是因为无法打开目录进行读取。如果出现这种情况,直接列出目录即可。
           */
          if ("file".equals(url.getProtocol())) {
            File file = new File(url.getFile());
            log.debug("Listing directory " + file.getAbsolutePath());
            if (file.isDirectory()) {
              log.debug("Listing " + url);
              children = Arrays.asList(file.list());
            }
          }else {throw e;}
        }

        // 3、递归列出子资源时要使用的URL前缀
        String prefix = url.toExternalForm();
        if (!prefix.endsWith("/")) {
          prefix = prefix + "/";
        }

        // 4、遍历直接子节点，添加文件
        for (String child : children) {
          String resourcePath = path + "/" + child;
          resources.add(resourcePath);
          URL childUrl = new URL(prefix + child);
          // 4.1递归子节点
          resources.addAll(list(childUrl, resourcePath));
        }
      }
      //5、返回资源文件路径集合
      return resources;
    } finally {
      if (is != null) {
        try {
          is.close();
        } catch (Exception ignored) {}
      }
    }
  }

  /**
   * 从给定的jar流中整理出所有的子文件名
   * List the names of the entries in the given {@link JarInputStream} that begin with the
   * specified {@code path}. Entries will match with or without a leading slash.
   *
   * @param jar The JAR input stream
   * @param path The leading path to match
   * @return The names of all the matching entries
   * @throws IOException If I/O errors occur
   */
  protected List<String> listResources(JarInputStream jar, String path) throws IOException {
    // Include the leading and trailing slash when matching names
    if (!path.startsWith("/")) {
      path = "/" + path;
    }
    if (!path.endsWith("/")) {
      path = path + "/";
    }

    // Iterate over the entries and collect those that begin with the requested path
    List<String> resources = new ArrayList<>();
    for (JarEntry entry; (entry = jar.getNextJarEntry()) != null;) {
      if (!entry.isDirectory()) {
        // Add leading slash if it's missing
        String name = entry.getName();
        if (!name.startsWith("/")) {
          name = "/" + name;
        }

        // Check file name
        if (name.startsWith(path)) {
          log.debug("Found resource: " + name);
          // Trim leading slash
          resources.add(name.substring(1));
        }
      }
    }
    return resources;
  }

  /**
   * 尝试解构给定的URL，找到包含资源的JAR文件的URL
   * @param url The URL of the JAR entry.
   * @return The URL of the JAR file, if one is found. Null if not.
   */
  protected URL findJarForResource(URL url) {
    log.debug("Find JAR URL: " + url);
    try {
      // 1、如果URL的文件部分本身也是一个URL，那就通过死循环 ,就是while(true) ,递归出最核心的URL
      for (;;) {
        url = new URL(url.getFile());
        log.debug("Inner URL: " + url);
      }
    } catch (MalformedURLException e) {
      // 必定会在某个点上发生(java.net.MalformedURLException: no protocol)，这作为循环的中断
      // 此时url已经是最核心的URL了，当然如果URL的文件部分本身不是一个URL，那URl还是最初的那个
      // @blog https://vimsky.com/examples/usage/url-getfile-method-in-java-with-examples.html
    }

    // 2、toExternalForm() 构造此 URL 的字符串表示形式,相当于toString
    StringBuilder jarUrl = new StringBuilder(url.toExternalForm());
    // 3、找.jar后缀的index
    int index = jarUrl.lastIndexOf(".jar");
    if (index >= 0) {
      // 3.1 将.jar之后的字符串删除  eq:  /test.jar/person ---> /test.jar
      jarUrl.setLength(index + 4);
      log.debug("Extracted JAR URL: " + jarUrl);
    }else {
      log.debug("Not a JAR: " + jarUrl);
      // 3.2 如果找不到".jar" 直接返回null
      return null;
    }

    try {
      URL testUrl = new URL(jarUrl.toString());
      // 4、通过魔法数,验证资源是否是jar包
      if (isJar(testUrl)) {
        // 4.1 是jar包则返回资源URL
        return testUrl;
      }else {
        // 4.2 检测出URl对应的资源文件不是jar包,则去检查文件系统中是否存在URL对应的资源文件。
        log.debug("Not a JAR: " + jarUrl);
        // 4.3 用testUrl.getFile() 替换 jarUrl   此处注意：,getFile只取协议之后的字符串
        jarUrl.replace(0, jarUrl.length(), testUrl.getFile());
        File file = new File(jarUrl.toString());
        // 4.4 假如文件不存在,则怀疑jarUrl.toString()中含有特殊字符 (使用类加载器加载资源时，如果路径出现空格,会自动编码成%20)
        if (!file.exists()) {
          try {
            // 4.5 使用UTF-8解码
            file = new File(URLDecoder.decode(jarUrl.toString(), "UTF-8"));
          } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Unsupported encoding?  UTF-8?  That's unpossible.");
          }
        }
        // 4.6 查看编码后文件是否存在
        if (file.exists()) {
          log.debug("Trying real file: " + file.getAbsolutePath());
          // 4.7 获得资源文件的URL路径，再次进行检测是否是jar包
          testUrl = file.toURI().toURL();
          if (isJar(testUrl)) {
            // 4.8 是jar包则返回URL
            return testUrl;
          }
        }
      }
    } catch (MalformedURLException e) {
      log.warn("Invalid JAR URL: " + jarUrl);
    }

    log.debug("Not a JAR: " + jarUrl);
    return null;
  }

  /**
   * 将Java包名转换为可以查找的路径
   * @param packageName The Java package name to convert to a path
   */
  protected String getPackagePath(String packageName) {
    return packageName == null ? null : packageName.replace('.', '/');
  }

  /**
   * 如果位于给定URL的资源是JAR文件，则返回true。委托给isJar(URL url, byte[] buffer)方法
   *
   * @param url The URL of the resource to test.
   */
  protected boolean isJar(URL url) {
    return isJar(url, new byte[JAR_MAGIC.length]);
  }

  /**
   * 所有的jar文件 前四个字节都是 0x50 0x4b 0x03 0x04
   *
   */
  protected boolean isJar(URL url, byte[] buffer) {
    try (InputStream is = url.openStream()) {
      is.read(buffer, 0, JAR_MAGIC.length);
      // 判断读出来的前四个字节是否等于JAR_MAGIC
      if (Arrays.equals(buffer, JAR_MAGIC)) {
        log.debug("Found JAR: " + url);
        return true;
      }
    } catch (Exception ignored) {}
    return false;
  }
}
