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
package org.apache.ibatis.scripting.xmltags;

/**
 * if SQL节点
 * e.q.
 *    <if test="title != null">
 *        AND title like #{title}
 *    </if>
 * @author Clinton Begin
 */
public class IfSqlNode implements SqlNode {
  /**
   * 表达式计算器
   */
  private ExpressionEvaluator evaluator;
  /**
   * test属性表达式,例如 title != null
   */
  private String test;
  /**
   * if节点下的文本元素
   */
  private SqlNode contents;

  public IfSqlNode(SqlNode contents, String test) {
    this.test = test;
    this.contents = contents;
    this.evaluator = new ExpressionEvaluator();
  }

  @Override
  public boolean apply(DynamicContext context) {
    // 如果满足条件,则apply,并返回true
    if (evaluator.evaluateBoolean(test, context.getBindings())) {
      // 通常这个contents里面就一个StaticTextSqlNode,他的apply方法是将text拼接到DynamicContext上去
      contents.apply(context);
      return true;
    }
    return false;
  }

}
