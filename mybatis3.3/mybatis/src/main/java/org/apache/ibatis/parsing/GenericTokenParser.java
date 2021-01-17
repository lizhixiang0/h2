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

/**
 * 通用标记解析器，处理${}参数
 * @author Clinton Begin
 */
public class GenericTokenParser {

  /**
   * 硬编码 ${
   */
  private final String openToken;
  /**
   * 硬编码 }
   */
  private final String closeToken;
  private final TokenHandler handler;

  public GenericTokenParser(String openToken, String closeToken, TokenHandler handler) {
    this.openToken = openToken;
    this.closeToken = closeToken;
    this.handler = handler;
  }

  /**
   * 这里面是一个算法，就是在将某个字符串里所有的${attr}替换掉
   * 要考虑到多种情况，比如
   *              ${id}}
   *              ${{id}
   *              _${id}_
   *              ${id}${id}
   *              {}${id}
   *              ${id}}
   *              {$$id}
   *              ${id}
   *              ${}id}
   * 特殊情况,如果${id}前面加了"\\"则不需要替换
   * 补充:默认attr里面不会出现"{、$、}",如果出现那也不管,如果是个空的${}那就替换成""
   * 提示:"${"看做一个整体
   * @param text
   * @return
   * @note 补充几个说明几个方法
   *              string.indexOf(String str, int fromIndex)               str的第一个匹配项在字符串string中的索引
   *              stringBuilder.append(char[] str, int offset, int len)   拿到字符数组里的一组字符,包含offset上的元素
   *              new String(char value[], int offset, int count)        根据字符数组里的一组字符创建String字符串
   */
  public String parse(String text) {
    StringBuilder builder = new StringBuilder();
    if (text != null && text.length() > 0) {
      char[] src = text.toCharArray();
      int offset = 0;
      int start = text.indexOf(openToken);
      // 一个text里可能有多个${},所以这里用循环
      while (start > -1) {
    	  //判断一下 ${ 前面是否是反斜杠，如果有反斜杠，那这个${}不做处理
        if (start > 0 && src[start - 1] == '\\') {
          // 例如src = [ss\\${skipped} variable${skipped}]   ==>  builder=[ss${]
          builder.append(src, offset, start - offset - 1).append(openToken);
          offset = start + openToken.length();
        } else {
          int end = text.indexOf(closeToken, start);
          if (end == -1) {
            builder.append(src, offset, src.length - offset);
            offset = src.length;
          } else {
            builder.append(src, offset, start - offset);
            offset = start + openToken.length();
            String content = new String(src, offset, end - offset);
            //得到一对大括号里的字符串后，调用handler.handleToken,替换变量
            builder.append(handler.handleToken(content));
            offset = end + closeToken.length();
          }
        }
        start = text.indexOf(openToken, offset);
      }
      if (offset < src.length) {
        builder.append(src, offset, src.length - offset);
      }
    }
    return builder.toString();
  }
  /**
   * sss${first_name} sss${initial} \\${last_name} reporting.
   * "ss\${skipped} variable
   * ${
   * @param text
   * @return
   */
  public String parse2(String text) {
    int start = text.indexOf(openToken);
    int close;
    int offset = 0;
    char[] chars = text.toCharArray();
    StringBuilder stringBuilder = new StringBuilder();
    while(start>-1){
      if(start>0 && chars[start-1]=='\\'){
        start = text.indexOf(openToken,start+1);
        if(start==-1){
          stringBuilder.append(chars,offset,chars.length-offset);
          start = -2;
        }else {
          stringBuilder.append(chars,offset,start);
        }
      }else {
        close = text.indexOf(closeToken,start);
        stringBuilder.append(chars,offset,start-offset);
        if(close>-1){
          String content = new String(chars, start+openToken.length(), close-start-openToken.length());
          stringBuilder.append(handler.handleToken(content));
          start = text.indexOf(openToken,close);
          offset = close+1;
        }else {
          stringBuilder.append(chars,start,chars.length-start);
          start = -2;
        }
      }
    }
    if(start==-1){
      stringBuilder.append(chars,offset,chars.length-offset);
    }
    return stringBuilder.toString().replaceAll("\\\\","");
  }

  /**
   * 学习指针的用法,在字符串里学会是必须要学会使用指针的！！！
   * sss${first_name} sss${initial} \\${last_name reporting.
   */

}


