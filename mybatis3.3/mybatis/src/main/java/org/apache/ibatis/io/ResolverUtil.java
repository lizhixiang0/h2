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
import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;

/**
 * 解析器：找到package下满足给定条件的所有类
 * 条件通常为：
 *          1、一个类继承或实现了另一个类，
 *          2、或者此类被指定的注解标记了
 * @author Tim Fennell
 */
public class ResolverUtil<T> {

  private static final Log log = LogFactory.getLog(ResolverUtil.class);

  /**
   *  内部接口，判断类是否应该被包含在ResolverUtil产生的结果中
   * A simple interface that specifies how to test classes to determine if they
   * are to be included in the results produced by the ResolverUtil.
   */
  public static interface Test {
    /**
     * 假如类满足条件就返回true
     */
    boolean matches(Class<?> type);
  }

  /**
   * 2、内部类 测试某类是否是构造函数中提供的父类型的子类,如果是返回true
   */
  public static class IsA implements Test {
    private Class<?> parent;

    public IsA(Class<?> parentType) {this.parent = parentType;}

    /**
     * 如果type是构造函数中提供的父类型的子类(包括父类型本身)，则返回true
     */
    @Override
    public boolean matches(Class<?> type) {
      return type != null && parent.isAssignableFrom(type);
    }

    @Override
    public String toString() {
      return "is assignable to " + parent.getSimpleName();
    }
  }

  /**
   * 3、内部类 判断类上是否有构造函数中提供的注解，如果是返回true
   */
  public static class AnnotatedWith implements Test {
    private Class<? extends Annotation> annotation;

    public AnnotatedWith(Class<? extends Annotation> annotation) {
      this.annotation = annotation;
    }

    /**
     * 意思就是:注释annotation是否在此type上
     */
    @Override
    public boolean matches(Class<?> type) {
      return type != null && type.isAnnotationPresent(annotation);
    }

    @Override
    public String toString() {
      return "annotated with @" + annotation.getSimpleName();
    }
  }

  /**
   * 匹配条件的类都放到这个set集合里
   */
  private Set<Class<? extends T>> matches = new HashSet<>();

  /**
   * 类加载器，用来查找类
   */
  private ClassLoader classloader;

  /**
   * 获得匹配条件的所有类
   */
  public Set<Class<? extends T>> getClasses() {
    return matches;
  }

  /**
   * 获得类加载器 ，没有设置就从当前线程里获取
   */
  public ClassLoader getClassLoader() {
    return classloader == null ? Thread.currentThread().getContextClassLoader() : classloader;
  }

  public void setClassLoader(ClassLoader classloader) {
    this.classloader = classloader;
  }

  /**
   * 收集给定包下，给定类的子类或其本身
   */
  public ResolverUtil<T> findImplementations(Class<?> parent, String... packageNames) {
    // 1、没有传递包名,就返回ResolverUtil，此时matches是个空set集合
    if (packageNames == null) {
      return this;
    }
    // 2、构建测试类,筛选目标类
    Test test = new IsA(parent);
    for (String pkg : packageNames) {
      // 3、核心方法
      find(test, pkg);
    }
    // 4、经过筛选后matches应该不是个空集合
    return this;
  }

  /**
   * 类似findImplementations
   */
  public ResolverUtil<T> findAnnotated(Class<? extends Annotation> annotation, String... packageNames) {
    if (packageNames == null) {
      return this;
    }

    Test test = new AnnotatedWith(annotation);
    for (String pkg : packageNames) {
      find(test, pkg);
    }

    return this;
  }

  /**
   * 主要的方法，找一个package下满足条件的所有类
   */
  public ResolverUtil<T> find(Test test, String packageName) {
    // 1、将Java包名转换为可以通过调用来查找的路径
    String path = getPackagePath(packageName);
    try {
        //2、通过VFS来深入jar包里面去找一个class
      List<String> children = VFS.getInstance().list(path);
      for (String child : children) {
        if (child.endsWith(".class")) {
          //3、 满足条件就添加到set集合中去
          addIfMatching(test, child);
        }
      }
    } catch (IOException ioe) {
      log.error("Could not read package: " + packageName, ioe);
    }

    return this;
  }

  /**
   * 将Java包名转换为可以通过调用来查找的路径
   * {@link ClassLoader#getResources(String)}.
   */
  protected String getPackagePath(String packageName) {
    return packageName == null ? null : packageName.replace('.', '/');
  }

  /**
   * Add the class designated by the fully qualified class name provided to the set of
   * resolved classes if and only if it is approved by the Test supplied.
   */
  @SuppressWarnings("unchecked")
  protected void addIfMatching(Test test, String fqn) {
    try {
      //
      String externalName = fqn.substring(0, fqn.indexOf('.')).replace('/', '.');
      // 获取类加载器
      ClassLoader loader = getClassLoader();
      log.debug("Checking to see if class " + externalName + " matches criteria [" + test + "]");
      // 类记载器加载类
      Class<?> type = loader.loadClass(externalName);
      if (test.matches(type)) {
        matches.add((Class<T>) type);
      }
    } catch (Throwable t) {
      log.warn("Could not examine class '" + fqn + "'" + " due to a " +t.getClass().getName() + " with message: " + t.getMessage());
    }
  }
}
