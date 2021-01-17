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

import static org.junit.Assert.assertEquals;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class GenericTokenParserTest {

  public static class VariableTokenHandler implements TokenHandler {
    private Map<String, String> variables;

    public VariableTokenHandler(Map<String, String> variables) {
      this.variables = variables;
    }

    @Override
    public String handleToken(String content) {
      return variables.get(content);
    }
  }

  /**
   * parse()应该具备通用性
   * 这里我学到了，这才是好的程序员应该具备的素质！测试用例应该这么写！！！
   */
  @Test
  public void shouldDemonstrateGenericTokenReplacement() {
    GenericTokenParser parser = new GenericTokenParser("${", "}", new VariableTokenHandler(new HashMap<String, String>() {
      {
        put("first_name", "James");
        put("initial", "T");
        put("last_name", "Kirk");
        put("", "");
      }
    }));

    assertEquals("sssJames T Kirk reporting.", parser.parse2("sss${first_name} ${initial} ${last_name} reporting."));
    assertEquals("Hello captain James T Kirk", parser.parse2("Hello captain ${first_name} ${initial} ${last_name}"));
    assertEquals("James T Kirk", parser.parse2("${first_name} ${initial} ${last_name}"));
    assertEquals("JamesTKirk", parser.parse2("${first_name}${initial}${last_name}"));
    assertEquals("{}JamesTKirk", parser.parse2("{}${first_name}${initial}${last_name}"));
    //assertEquals("}JamesTKirk", parser.parse2("}${first_name}${initial}${last_name}"));

    //assertEquals("}James{{T}}Kirk", parser.parse2("}${first_name}{{${initial}}}${last_name}"));
    //assertEquals("}James}T{Kirk", parser.parse2("}${first_name}}${initial}{${last_name}"));
    //assertEquals("}James}T{Kirk", parser.parse2("}${first_name}}${initial}{${last_name}"));
    //assertEquals("}James}T{Kirk{{}}", parser.parse2("}${first_name}}${initial}{${last_name}{{}}"));
    //assertEquals("}James}T{Kirk{{}}", parser.parse2("}${first_name}}${initial}{${last_name}{{}}${}"));

    //assertEquals("{$$something}JamesTKirk", parser.parse2("{$$something}${first_name}${initial}${last_name}"));
    //assertEquals("${", parser.parse2("${"));
    //assertEquals("}", parser.parse2("}"));
    //assertEquals("Hello ${ this is a test.", parser.parse2("Hello ${ this is a test."));
    //ssertEquals("Hello } this is a test.", parser.parse2("Hello } this is a test."));
    //assertEquals("Hello } ${ this is a test.", parser.parse2("Hello } ${ this is a test."));
  }

  public static void main(String[] args) {
    GenericTokenParser parser = new GenericTokenParser("${", "}", new VariableTokenHandler(new HashMap<String, String>() {
      {
        put("first_name", "James");
        put("initial", "T");
        put("last_name", "Kirk");
        put("", "");
      }
    }));
    System.out.println(parser.parse("${}first_name}"));
    System.out.println(parser.parse("${{first_name}"));
  }


  /**
   * 不应插值跳过的变量,加上\\可以 跳过标记处理
   */
  @Test
  public void shallNotInterpolateSkippedVaiables() {
    GenericTokenParser parser = new GenericTokenParser("${", "}", new VariableTokenHandler(new HashMap<>()));

    assertEquals("${skipped} variable", parser.parse2("\\${skipped} variable"));
    assertEquals("This is a ${skipped} variable", parser.parse2("This is a \\${skipped} variable"));
   assertEquals("null ${skipped} variable", parser.parse2("${skipped} \\${skipped} variable"));
   assertEquals("The null is ${skipped} variable", parser.parse2("The ${skipped} is \\${skipped} variable"));
  }

  /**
   * 应该在Jdk 7 u 6上快速解析
   */
  @Test(timeout = 1000)
  public void shouldParseFastOnJdk7u6() {
    // issue #760
    GenericTokenParser parser = new GenericTokenParser("${", "}", new VariableTokenHandler(new HashMap<String, String>() {
      {
        put("first_name", "James");
        put("initial", "T");
        put("last_name", "Kirk");
        put("", "");
      }
    }));

    StringBuilder input = new StringBuilder();
    for (int i = 0; i < 10000; i++) {
      input.append("${first_name} ${initial} ${last_name} reporting. ");
    }
    StringBuilder expected = new StringBuilder();
    for (int i = 0; i < 10000; i++) {
      expected.append("James T Kirk reporting. ");
    }
    assertEquals(expected.toString(), parser.parse(input.toString()));
  }

}
