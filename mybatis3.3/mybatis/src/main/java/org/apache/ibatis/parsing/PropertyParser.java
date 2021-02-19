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
package org.apache.ibatis.parsing;

import java.util.Properties;

/**
 *
 */
/**
 * 属性解析器
 * @author Clinton Begin
 */
public class PropertyParser {

  private PropertyParser() {}

  /**
   * 静态方法 将${id}中的id替换成variables中对应的值
   * @param string  不一定是标准的${id},情况比较多，例如 ${id}} ，所以使用GenericTokenParser来进行处理
   * @param variables hashTable结构   例如 id : 1
   * @return
   */
  public static String parse(String string, Properties variables) {
    VariableTokenHandler handler = new VariableTokenHandler(variables);
    //${}符号是mybatis配置文件中的占位符
    GenericTokenParser parser = new GenericTokenParser("${", "}", handler);
    return parser.parse(string);
  }

  private static class VariableTokenHandler implements TokenHandler {
    /**
     * Properties继承了Hashtable
     */
    private Properties variables;

    public VariableTokenHandler(Properties variables) {
      this.variables = variables;
    }

    @Override
    public String handleToken(String content) {
      if (variables != null && variables.containsKey(content)) {
        // 在 variables中找到了key ,则返回对应的value
        return variables.getProperty(content);
      }
      //如果在给定的Properties中找不到,则拼装成原来的样子返回
      return "${" + content + "}";
    }
  }
}
