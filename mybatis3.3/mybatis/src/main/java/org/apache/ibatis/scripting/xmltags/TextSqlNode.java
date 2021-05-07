/*
 *    Copyright 2009-2013 the original author or authors.
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

import java.util.regex.Pattern;

import org.apache.ibatis.parsing.GenericTokenParser;
import org.apache.ibatis.parsing.TokenHandler;
import org.apache.ibatis.scripting.ScriptingException;
import org.apache.ibatis.type.SimpleTypeRegistry;

/**
 * 文本SQL节点（CDATA|TEXT）
 * @author Clinton Begin
 */
public class TextSqlNode implements SqlNode {
  /**
   * sql文本
   */
  private String text;
  /**
   * 注入过滤器
   */
  private Pattern injectionFilter;

  public TextSqlNode(String text) {
    this(text, null);
  }

  public TextSqlNode(String text, Pattern injectionFilter) {
    this.text = text;
    this.injectionFilter = injectionFilter;
  }


  @Override
  public boolean apply(DynamicContext context) {
    // 如果是TextSqlNode节点，需要使用绑定记号解析器处理下text再拼接到context中去
    GenericTokenParser parser = createParser(new BindingTokenParser(context, injectionFilter));
    context.appendSql(parser.parse(text));
    return true;
  }


  /**
   * 绑定记号解析器，这个会对包含${}的动态文本进行处理  (有个面试题目是,什么时候用${},什么时候用#{})
   */
  private static class BindingTokenParser implements TokenHandler {

    private DynamicContext context;
    /**
     * 通常为null,这个可以帮助我们检查是否有注入
     */
    private Pattern injectionFilter;

    public BindingTokenParser(DynamicContext context, Pattern injectionFilter) {
      this.context = context;
      this.injectionFilter = injectionFilter;
    }

    /**
     * 对包含${}的动态文本进行处理  (有个面试题目是,什么时候用${},什么时候用#{})
     * @link "https://blog.csdn.net/siwuxie095/article/details/79190856
     * @note
     *       非要用${}的时候那都是数据库的限制!!!能用 #{} 的地方就用 #{},少用 ${} !
     *       sql语句里面,如果涉及到动态表名,那必须使用${}
     *       如果涉及到orderBy查询,那也必须使用${},因为order by后边必须跟字段名，这个字段名不能带引号,带引号会被识别会字符串，而不是字段
     * @param content
     * @return
     */
    @Override
    public String handleToken(String content) {
      Object parameter = context.getBindings().get("_parameter");
      // 1、可以看到提取出_parameter值之后,又以value为健名放入了容器,这意味着如果传入基本类型如字符串时就写${value}才能够成功取值。
      if (parameter == null) {
        context.getBindings().put("value", null);
      } else if (SimpleTypeRegistry.isSimpleType(parameter.getClass())) {
        context.getBindings().put("value", parameter);
      }
      // 2、利用表达式（content）和ognl从上下文提取值
      Object value = OgnlCache.getValue(content, context.getBindings());
      // 3、将值转化为String类型,如果是null就转化为空字符串 (所以说${}转化后没有'')
      String srtValue = (value == null ? "" : String.valueOf(value));
      // 4、因为${}有注入的危险,这个是可以写正则去检测的  （但是没有提供接口去设置）
      checkInjection(srtValue);
      // 5、最次是个""
      return srtValue;
    }

    /**
     * 检查是否有注入
     * @param value
     */
    private void checkInjection(String value) {
      if (injectionFilter != null && !injectionFilter.matcher(value).matches()) {
        throw new ScriptingException("Invalid input. Please conform to regex" + injectionFilter.pattern());
      }
    }
  }

  /**
   * 判断是否是动态sql,只要text中包含了'${}'就属于动态sql
   */
  public boolean isDynamic() {
    DynamicCheckerTokenParser checker = new DynamicCheckerTokenParser();
    GenericTokenParser parser = createParser(checker);
    parser.parse(text);
    return checker.isDynamic();
  }

  private GenericTokenParser createParser(TokenHandler handler) {
    return new GenericTokenParser("${", "}", handler);
  }

  /**
   * 动态SQL检查器,判断有没有${}
   */
  private static class DynamicCheckerTokenParser implements TokenHandler {

    private boolean isDynamic;

    public DynamicCheckerTokenParser() {}

    public boolean isDynamic() {
      return isDynamic;
    }

    @Override
    public String handleToken(String content) {
      // 只要text中包含了'${}',GenericTokenParser就会调用handleToken,此时isDynamic会被设置成true
      this.isDynamic = true;
      return null;
    }
  }

}
