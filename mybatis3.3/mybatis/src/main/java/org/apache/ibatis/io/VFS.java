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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;

/**
 * Provides a very simple API for accessing resources within an application server.
 * 抽象类 虚拟文件系统(VFS virtual File System),用来读取服务器里的资源
 *
 * @author Ben Gunter
 */
public abstract class VFS {

  private static final Log log = LogFactory.getLog(ResolverUtil.class);

  /**
   * 1、默认提供2个实现类 JBoss6VFS,DefaultVFS
   */
  public static final Class<?>[] IMPLEMENTATIONS = { JBoss6VFS.class, DefaultVFS.class };

  /**
   * 2、这里是提供一个用户扩展点，可以让用户自定义VFS实现
   */
  public static final List<Class<? extends VFS>> USER_IMPLEMENTATIONS = new ArrayList<>();

  private static VFS instance;

  @SuppressWarnings("unchecked")
  public static VFS getInstance() {
    // 1、已经实例化了，直接返回 （单例模式）
    if (instance != null) {
      return instance;
    }
    // 2、先尝试用户实现，然后再尝试内置实现
    List<Class<? extends VFS>> impls = new ArrayList<>();
    impls.addAll(USER_IMPLEMENTATIONS);
    impls.addAll(Arrays.asList((Class<? extends VFS>[]) IMPLEMENTATIONS));

    //3、遍历实现类
    VFS vfs = null;
    for (int i = 0; vfs == null || !vfs.isValid(); i++) {
      Class<? extends VFS> impl = impls.get(i);
      try {
        // 3.1 实例化
        vfs = impl.newInstance();
        // 3.2 查看是否对当前环境适用
        if (vfs == null || !vfs.isValid()) {
          log.debug("VFS implementation " + impl.getName() +" is not valid in this environment.");
        }
      } catch (InstantiationException | IllegalAccessException e) {
        log.error("Failed to instantiate " + impl, e);
        return null;
      }
    }

    log.debug("Using VFS adapter " + vfs.getClass().getName());
    // 4、将当前实例赋值给类属性
    VFS.instance = vfs;
    // 5、返回
    return VFS.instance;
  }

  /**
   * 添加用户自定义的VFS实现
   */
  public static void addImplClass(Class<? extends VFS> clazz) {
    if (clazz != null) {
      USER_IMPLEMENTATIONS.add(clazz);
    }
  }

  /**
   * 根据类名查找类并返回
   * @param className The class name
   */
  protected static Class<?> getClass(String className) {
    try {
      return Thread.currentThread().getContextClassLoader().loadClass(className);
    } catch (ClassNotFoundException e) {
      log.debug("Class not found: " + className);
      return null;
    }
  }

  /**
   * 根据类名和类方法名以及类参数类型，返回类方法
   *
   * @param clazz The class to which the method belongs.
   * @param methodName The name of the method.
   * @param parameterTypes The types of the parameters accepted by the method.
   */
  protected static Method getMethod(Class<?> clazz, String methodName, Class<?>... parameterTypes) {
    if (clazz == null) {
      return null;
    }
    try {
      // 获取Method
      return clazz.getMethod(methodName, parameterTypes);
    } catch (SecurityException e) {
      log.error("Security exception looking for method " + clazz.getName() + "." + methodName + ".  Cause: " + e);
      return null;
    } catch (NoSuchMethodException e) {
      log.error("Method not found " + clazz.getName() + "." + methodName + "." + methodName + ".  Cause: " + e);
      return null;
    }
  }

  /**
   * 在一个对象上调用一个方法并返回它返回的任何东西。
   *
   * @param method The method to invoke.
   * @param object The instance or class (for static methods) on which to invoke the method.
   * @param parameters The parameters to pass to the method.
   */
  @SuppressWarnings("unchecked")
  protected static <T> T invoke(Method method, Object object, Object... parameters)
      throws IOException, RuntimeException {
    try {
      // 调用method.invoke方法
      return (T) method.invoke(object, parameters);
    } catch (IllegalArgumentException | IllegalAccessException e) {
      throw new RuntimeException(e);
    } catch (InvocationTargetException e) {
      if (e.getTargetException() instanceof IOException) {
        throw (IOException) e.getTargetException();
      } else {
        throw new RuntimeException(e);
      }
    }
  }

  /**
   * 通过类加载器获取指定路径中所有资源的URl ,返回list
   * @param path The resource path.
   * @return A list of {@link URL}s, as returned by {@link ClassLoader#getResources(String)}.
   * @throws IOException If I/O errors occur
   */
  protected static List<URL> getResources(String path) throws IOException {
    return Collections.list(Thread.currentThread().getContextClassLoader().getResources(path));
  }

  /**
   * 对当前环境适用则返回true
   */
  public abstract boolean isValid();

  /**
   * 递归得列出给定的url下所有文件的资源路径 ,子类实现
   * @param url 标识要列出的资源的URL（或者是文件或者是文件目录）。 eq:file:/D:/JetBrains/workspace/h2/mybatis3.3/mybatis-test/target/classes/com/mybatis/lizx/model
   * @param forPath 由URL标识的资源的路径。通常，这是传递给{@link #getResources(String)}以获取资源URL的值。eq: com/mybatis/lizx/model
   */
  protected abstract List<String> list(URL url, String forPath) throws IOException;

  /**
   * 递归得列出给定的path下所有文件的资源路径
   * @param path The path of the resource(s) to list.
   * @return A list containing the names of the child resources.
   * @throws IOException If I/O errors occur
   */
  public List<String> list(String path) throws IOException {
    List<String> names = new ArrayList<>();
    for (URL url : getResources(path)) {
      names.addAll(list(url, path));
    }
    return names;
  }
}
