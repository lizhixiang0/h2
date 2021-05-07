/*
 *    Copyright 2009-2014 the original author or authors.
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


import ognl.ClassResolver;
import ognl.Ognl;
import ognl.OgnlException;
import org.apache.ibatis.builder.BuilderException;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Ognl解析器
 * @author Eduardo Macarron
 */
public final class OgnlCache {
  /**
   * 自定义ognl类解析器,不写成多态形式居然找不到,靠...
   */
  private static final ClassResolver CLASS_RESOLVER = new OgnlClassResolver();

  /**
   * 缓存器、因为ognl性能不好，所以加了一个缓存,同样的东西解析过一次就缓存到ConcurrentHashMap<>里
   */
  private static final Map<String, Object> expressionCache = new ConcurrentHashMap<>();

  /**
   * Prevent Instantiation of Static Class
   */
  private OgnlCache() {}

  /**
   * 利用表达式从root中提取值
   * @param expression 表达式
   * @param root 被解析的对象
   * @return 解析结果
   */
  public static Object getValue(String expression, Object root) {
    try {
      // 1、创建并返回一个新的标准命名上下文，用于计算OGNL表达式。
      Map context = Ognl.createDefaultContext(root, CLASS_RESOLVER);
      // 2、解析给定的OGNL表达式并返回表达式的树形表示形式
      Object tree = parseExpression(expression);
      // 3、计算给定的OGNL表达式树，从给定的根对象中提取一个值
      return Ognl.getValue(tree, context, root);
    } catch (OgnlException e) {
      throw new BuilderException("Error evaluating expression '" + expression + "'. Cause: " + e, e);
    }
  }

  /**
   *  解析给定的OGNL表达式
   */
  private static Object parseExpression(String expression) throws OgnlException {
    // 1、先从缓存中拿
    Object node = expressionCache.get(expression);
    if (node == null) {
      // 2、拿不到,利用Ognl解析给定的OGNL表达式并返回表达式的树形表示形式
      node = Ognl.parseExpression(expression);
      // 3、放到缓存里去
      expressionCache.put(expression, node);
    }
    // 4、返回
    return node;
  }

}
