/*
 *    Copyright 2014 the original author or authors.
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

package org.apache.ibatis.scripting.xmltags;

import java.util.HashMap;
import java.util.Map;

import ognl.ClassResolver;

import org.apache.ibatis.io.Resources;

/**
 * 自定义ognl类解析器，其行为与ognl的DefaultClassResolver相同。但是使用Resources实用程序类来查找目标类，而不是Class.forName(String)
 * 这里使用Resources.classForName去加载类不是为了不执行类中的static,而是为了保证一定能把类加载进虚拟机
 * @author Daniel Guggi
 * @link "https://blog.csdn.net/Nineteenyy/article/details/88671289
 */
public class OgnlClassResolver implements ClassResolver {
  /**
   * 创建一个容器,不知初始化为啥是101
   */
  private Map<String, Class<?>> classes = new HashMap<>(101);

  @Override
  public Class classForName(String className, Map context) throws ClassNotFoundException {
    Class<?> result;
    // 1、先从容器中找
    if ((result = classes.get(className)) == null) {
      try {
        // 2、找不到使用资源加载器，加载类
        result = Resources.classForName(className);
      } catch (ClassNotFoundException e1) {
        // 2.1、抛异常了,假如类名没有'.',那就拼接成java.lang.className继续找
        if (className.indexOf('.') == -1) {
          result = Resources.classForName("java.lang." + className);
          classes.put("java.lang." + className, result);
        }
      }
      // 3、塞入容器
      classes.put(className, result);
    }
    // 4、返回clazz
    return result;
  }
}
