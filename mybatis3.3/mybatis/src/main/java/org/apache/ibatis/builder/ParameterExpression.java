/*
 * Copyright 2012-2013 MyBatis.org.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ibatis.builder;

import java.util.HashMap;

/**
 * 内联参数表达式解析器,支持很多语法形式,结合测试类来看，具体不去探究了
 * e.q.
 *  Map<String, String> result = new ParameterExpression("id, attr1=val1, attr2=val2, attr3=val3");
 *     Assert 4 == result.size()
 *     Assert id == result.get("property";
 *     Assert val1 == result.get("attr1");
 *     Assert val2 == result.get("attr2");
 *     Assert "val3 ==  result.get("attr3");
 *
 * @author Frank D. Martinez [mnesarco]
 */
public class ParameterExpression extends HashMap<String, String> {

  private static final long serialVersionUID = -2417552199605158680L;
  /**
   * 32之前的ascii字符都是一群控制字符,没啥意义
   * @link "https://baike.baidu.com/item/ASCII/309296?fromtitle=ASCII%E7%BC%96%E7%A0%81&fromid=3712529&fr=aladdin
   */
  private static final char BLANK = 0x20;



  /**
   * 构造方法,传入参数直接解析
   * @param expression  property,javaType=int,jdbcType=NUMERIC
   */
  public ParameterExpression(String expression) {
    parse(expression);
  }

  /**
   * 解析表达式
   * @param expression property,javaType=int,jdbcType=NUMERIC
   */
  private void parse(String expression) {
    // 1、找表达式从0开始第一个不是空格的字符位置
    int p = skipWS(expression, 0);
    // 2、如果这个字符是"(",则处理表达式
    if (expression.charAt(p) == '(') {
      expression(expression, p + 1);
    } else {
      // 3、如果这个字符不是"(",处理属性
      property(expression, p);
    }
  }

  /**
   * 特殊情况1
   * @param expression   (id.toString()), attr1=val1, attr2=val2, attr3=val3
   * @param left 1
   */
  private void expression(String expression, int left) {
    int match = 1;
    int right = left + 1;
    while (match > 0) {
      /*==============连续碰到两个"(("就跳出循环,此时right在","的位置上================*/
      if (expression.charAt(right) == ')') {
        match--;
      } else if (expression.charAt(right) == '(') {
        match++;
      }
      /*===============================*/
      right++;
    }
    put("expression", expression.substring(left, right - 1));
    // 将括号里面的id.toString()截取出来,然后继续处理其他属性,此时right在","的位置上
    jdbcTypeOpt(expression, right);
  }

  /**
   * 获取表达式中的各种信息
   * @param expression property,javaType=int,jdbcType=NUMERIC
   * @param left 0
   */
  private void property(String expression, int left) {
    if (left < expression.length()) {
      // 1、首先，得到逗号或者冒号之前的字符串，并将其加入到property
      int right = skipUntil(expression, left, ",:");
      put("property", trimmedStr(expression, left, right));
      // 2、第二，处理javaType、jdbcType等属性
      jdbcTypeOpt(expression, right);
    }
  }

  /**
   * 返回从第P个字符开始，第一次ascii码值大于空格的index,其实就是找p后面第一个不是空格的字符
   * 如果没有空格就返回表达式的长度
   * @param expression 表达式
   * @param p  从表达式的第几个字符开始
   * @return int
   */
  private int skipWS(String expression, int p) {
    for (int i = p; i < expression.length(); i++) {
      if (expression.charAt(i) > BLANK) {
        return i;
      }
    }
    return expression.length();
  }

  /**
   * 找到特殊字符出现在expression中的位置
   * @param expression  property,javaType=int,jdbcType=NUMERIC
   * @param p 0
   * @param endChars , | :
   * @return 8 （endChars中的字符出现在expression的位置）
   */
  private int skipUntil(String expression, int p, final String endChars) {
    for (int i = p; i < expression.length(); i++) {
      char c = expression.charAt(i);
      if (endChars.indexOf(c) > -1) {
        return i;
      }
    }
    return expression.length();
  }

  /**
   * 处理其他属性
   * @param expression  property,javaType=int,jdbcType=NUMERIC
   * @param p , 或 :的位置 ，此时是8
   */
  private void jdbcTypeOpt(String expression, int p) {
    // 1、跳过p后面的非常用字符
    p = skipWS(expression, p);
    if (p < expression.length()) {
      // 第一个property后可能是","或 ":"
      if (expression.charAt(p) == ':') {
        // 特殊情况：id:VARCHAR, attr1=val1, attr2=val2 ,此时p为2
        jdbcType(expression, p + 1);
      } else if (expression.charAt(p) == ',') {
        option(expression, p + 1);
      } else {
        throw new BuilderException("Parsing error in {" + new String(expression) + "} in position " + p);
      }
    }
  }

  /**
   * 特殊情况2
   * @param expression  id:VARCHAR, attr1=val1, attr2=val2
   * @param p 此时p为2
   */
  private void jdbcType(String expression, int p) {
    // 1、跳过空白
    int left = skipWS(expression, p);
    // 2、找到","的位置
    int right = skipUntil(expression, left, ",");
    if (right > left) {
      // 3、这里可以看到，如果以这种格式写，默认:后面是java类型
      put("jdbcType", trimmedStr(expression, left, right));
    } else {
      throw new BuilderException("Parsing error in {" + new String(expression) + "} in position " + p);
    }
    // 4、继续解析其他属性
    option(expression, right + 1);
  }

  /**
   * 处理表达式里的javaType和jdbcType等属性
   * @param expression property,javaType=int,jdbcType=NUMERIC
   * @param p  9
   */
  private void option(String expression, int p) {
    // 1、老惯例,跳过空白
    int left = skipWS(expression, p);
    if (left < expression.length()) {
      // 2、找到"="的位置
      int right = skipUntil(expression, left, "=");
      // 3、截取javaType
      String name = trimmedStr(expression, left, right);
      left = right + 1;
      // 4、找到","的位置
      right = skipUntil(expression, left, ",");
      // 5、截取int
      String value = trimmedStr(expression, left, right);
      // 6、存到容器里
      put(name, value);
      // 7、递归调用option，进行逗号后面一个属性的解析
      option(expression, right + 1);
    }
  }

  /**
   * 裁掉property两边的非常用字符（通常是空格）
   * @param str  property,javaType=int,jdbcType=NUMERIC
   * @param start  0
   * @param end end所在的位置,此时是8
   * @return property
   */
  private String trimmedStr(String str, int start, int end) {
    while (str.charAt(start) <= BLANK) {
      start++;
    }
    while (str.charAt(end - 1) <= BLANK) {
      end--;
    }
    return start >= end ? "" : str.substring(start, end);
  }

}
