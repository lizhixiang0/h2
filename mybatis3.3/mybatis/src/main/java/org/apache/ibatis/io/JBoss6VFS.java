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

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;

/**
 * 调用Jboss6的VFS API
 * jdk自身提供的资源导航，需要判定文件的类型，操作比较繁琐。在VFS中我们将所有的类型抽象为一个类型-VirtualFile
 * 简而言之就是调用外部API来处理资源
 * @author Ben Gunter
 */
public class JBoss6VFS extends VFS {
  private static final Log log = LogFactory.getLog(ResolverUtil.class);

  /**
   * 一个类，模拟JBoss的 VirtualFile类的一个很小的子集
   */
  static class VirtualFile {
    static Class<?> VirtualFile;
    static Method getPathNameRelativeTo, getChildrenRecursively;

    Object virtualFile;

    VirtualFile(Object virtualFile) {
      this.virtualFile = virtualFile;
    }

    String getPathNameRelativeTo(VirtualFile parent) {
      try {
        return invoke(getPathNameRelativeTo, virtualFile, parent.virtualFile);
      } catch (IOException e) {
        // This exception is not thrown by the called method
        log.error("This should not be possible. VirtualFile.getPathNameRelativeTo() threw IOException.");
        return null;
      }
    }

    List<VirtualFile> getChildren() throws IOException {
      List<?> objects = invoke(getChildrenRecursively, virtualFile);
      List<VirtualFile> children = new ArrayList<VirtualFile>(objects.size());
      for (Object object : objects) {
        children.add(new VirtualFile(object));
      }
      return children;
    }
  }

  /**
   * 一个类，它模仿JBoss VFS类的一个很小的子集。
   * 转换jdk或者RUL资源到VirtualFile，虚拟文件需要一个root，VFS类知道如何根据一个URL取得虚拟文件
   */
  static class VFS {
    static Class<?> VFS;
    static Method getChild;

    private VFS() {
      // Prevent Instantiation
    }

    static VirtualFile getChild(URL url) throws IOException {
      Object o = invoke(getChild, VFS, url);
      return o == null ? null : new VirtualFile(o);
    }
  }

  /**
   * 标志，指示此VFS对当前环境是否有效
   */
  private static Boolean valid;

  /**
   * 找到所需JBoss 6 VFS的所有类和方法，并验证，然后赋值给内部类
   */
  protected static synchronized void initialize() {
    if (valid == null) {
      // 先假定有效。如果出了什么问题，它会被翻转。
      valid = Boolean.TRUE;

      // 查找并验证所需的类，getClass方法定义在抽象父类中
      VFS.VFS = checkNotNull(getClass("org.jboss.vfs.VFS"));
      VirtualFile.VirtualFile = checkNotNull(getClass("org.jboss.vfs.VirtualFile"));

      // 查找并验证所需的方法
      VFS.getChild = checkNotNull(getMethod(VFS.VFS, "getChild", URL.class));
      VirtualFile.getChildrenRecursively = checkNotNull(getMethod(VirtualFile.VirtualFile,"getChildrenRecursively"));
      VirtualFile.getPathNameRelativeTo = checkNotNull(getMethod(VirtualFile.VirtualFile,"getPathNameRelativeTo", VirtualFile.VirtualFile));

      // 验证API没有更改
      checkReturnType(VFS.getChild, VirtualFile.VirtualFile);
      checkReturnType(VirtualFile.getChildrenRecursively, List.class);
      checkReturnType(VirtualFile.getPathNameRelativeTo, String.class);
    }
  }

  /**
   * 验证提供的对象引用是否为空。如果它是null，那么这个VFS被标记对当前环境无效。
   * @param object The object reference to check for null.
   */
  protected static <T> T checkNotNull(T object) {
    if (object == null) {
      setInvalid();
    }
    return object;
  }

  /**
   * 验证方法的返回类型是否符合预期。如果不是，那么这个VFS在当前环境中被标记为无效。
   * @param method The method whose return type is to be checked.
   * @param expected A type to which the method's return type must be assignable.
   * @see Class#isAssignableFrom(Class)
   */
  protected static void checkReturnType(Method method, Class<?> expected) {
    if (method != null && !expected.isAssignableFrom(method.getReturnType())) {
      log.error("Method " + method.getClass().getName() + "." + method.getName()+ "(..) should return " + expected.getName() + " but returns " + method.getReturnType().getName() + " instead.");
      setInvalid();
    }
  }

  /**
   * 标志，指示此VFS对当前环境是无效
   */
  protected static void setInvalid() {
    if (JBoss6VFS.valid.equals(Boolean.TRUE)) {
      log.debug("JBoss 6 VFS API is not available in this environment.");
      JBoss6VFS.valid = Boolean.FALSE;
    }
  }

  /**
   * 类一加载就执行initialize
   */
  static {
    initialize();
  }

  @Override
  public boolean isValid() {
    return valid;
  }

  @Override
  public List<String> list(URL url, String path) throws IOException {
    VirtualFile directory;
    // 1、根据url取得虚拟文件目录,拿不到直接返回空集合
    directory = VFS.getChild(url);
    if (directory == null) {
      return Collections.emptyList();
    }
    // 2、处理下path路径
    if (!path.endsWith("/")) {
      path += "/";
    }
    // 3、获得虚拟目录的子虚拟文件
    List<VirtualFile> children = directory.getChildren();
    // 4、创建集合容器
    List<String> names = new ArrayList<>(children.size());
    // 5、遍历获得子文件相对目录的的路径名
    for (VirtualFile vf : children) {
      names.add(path + vf.getPathNameRelativeTo(directory));
    }
    // 6、返回集合
    return names;
  }
}
