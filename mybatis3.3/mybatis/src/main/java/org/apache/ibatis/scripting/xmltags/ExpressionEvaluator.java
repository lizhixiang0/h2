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

import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.builder.BuilderException;

/**
 * 1、If节点用到的,判断表达式是否正确
 *    例如：<if test="status != null and status !=''">
 *              and status = #{status}
 *         </if>
 *
 * 2、forEach节点用到
 *         select * from t_blog where id in
 *         <foreach collection="list" index="index" item="item" open="(" separator="," close=")">
 *                 #{item}
 *         </foreach>
 *
 * @author Clinton Begin
 */
public class ExpressionEvaluator {

    /**
     * 通过Ognl在对象找对应的属性来判断表达式是否正确
     * @param expression  "username == 'java'"
     * @param parameterObject   new Author(1, 'java', "******", "cbegin@apache.org", "N/A", Section.NEWS)
     * @return true || false
     */
  public boolean evaluateBoolean(String expression, Object parameterObject) {
	// 1、通过Ognl来判断表达式是否正确
    Object value = OgnlCache.getValue(expression, parameterObject);
    // 2、如果value是Boolean类型,那就直接返回
    if (value instanceof Boolean) {
      return (Boolean) value;
    }
    // 3、如果value是Number类型,为0则返回false,不为0返回true
    if (value instanceof Number) {
        return !new BigDecimal(String.valueOf(value)).equals(BigDecimal.ZERO);
    }
    // 4、如果value既不是Boolean类型也不是Number类型，如果是null就返回false,不是就返回true
    return value != null;
  }

    /**
     * 利用Ognl在对象找目标集合（java是list实现了Iterable）
     * @param expression 目标集合的名字
     * @param parameterObject 对象
     * @return 迭代器
     */
  public Iterable<?> evaluateIterable(String expression, Object parameterObject) {
	// 1、利用OgnlCache.getValue直接找到Iterable型或数组型或Map型
    Object value = OgnlCache.getValue(expression, parameterObject);
    // 2、如果value为null ,直接抛出异常
    if (value == null) {
      throw new BuilderException("The expression '" + expression + "' evaluated to a null value.");
    }
    // 3、如为value是迭代器类型,转化下返回
    if (value instanceof Iterable) {
      return (Iterable<?>) value;
    }
    // 4、如果value不是迭代器类型,判断是不是数组类型
    if (value.getClass().isArray()) {
    	// 4.1、如果是array，则把他变成一个List<Object>,不能用Arrays.asList()，因为array可能是基本型（int[]）
        int size = Array.getLength(value);
        List<Object> answer = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            Object o = Array.get(value, i);
            answer.add(o);
        }
        return answer;
    }
    // 5、如果value不是迭代器和数组类型类型,判断是不是集合类型，这个倒是省事，直接entrySet()
    if (value instanceof Map) {
      return ((Map) value).entrySet();
    }
    // 6、啥都不是直接报错。。。
    throw new BuilderException("Error evaluating expression '" + expression + "'.  Return value (" + value + ") was not iterable.");
  }

}
