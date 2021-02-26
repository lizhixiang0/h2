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
package org.apache.ibatis.reflection.property;

import lombok.Data;

import java.util.Iterator;

/**
 * 属性描述符解析器（分词器）,使用到了迭代器模式
 * 作用：解析属性表达式，比如结果映射或者执行SQL传参，<resultMap> 的 property 属性或 sql 元素中的参数变量占位 #{} 中的内容都可能是一个属性表达式
 * 例如: person.name
 *
 * @author Clinton Begin
 */
@Data
public class PropertyTokenizer implements Iterable<PropertyTokenizer>, Iterator<PropertyTokenizer> {
  /**
   * 表达式最顶层的属性名
   */
  private String name;

  /**
   * 当前表达式的索引名
   */
  private String indexedName;

  /**
   * 索引下标
   */
  private String index;

  /**
   * 子表达式
   */
  private String children;

  /**
   * 第一步、首先处理fullname为name和children属性赋值
   *      如果传到构造方法的fullname包含了'.',则表示他描述的是一个嵌套的多层属性的引用，对于这种场景，PropertyTokenizer会获取第一个'.'前面的部分作为name属性，并把'.'后面的内容赋值为children属性。
   *      如果传到构造方法的fullname不包含'.',直接把fullname赋值给name属性,children属性赋值为null
   *
   * 第二步、对name进行进一步的解析,如果包含了字符[,则获取从[到name属性的倒数第二个字符之间的内容赋值给index属性,并把字符[前面的内容赋值给name
   *        如果name属性中不包含字符[,不进行任何操作。
   *
   *  * 例一、 person[0].name,将依次取得
   *  *                                      name = person
   *  *                                      indexedName = person[0]
   *  *                                      index = 0
   *  *                                      children = name
   *  *
   *  * 例二、person.name  将依次取得
   *  *                    name =   person
   *  *                    indexedName = person
   *  *                    children = name
   *  *                    index = null
   * @param fullname
   */
  public PropertyTokenizer(String fullname) {
    //找'.'
    int delim = fullname.indexOf('.');
    if (delim > -1) {
      name = fullname.substring(0, delim);
      children = fullname.substring(delim + 1);
    } else {
      //找不到.的话，取全部部分
      name = fullname;
      children = null;
    }
    indexedName = name;
    //找'[',把中括号[]里的数字给解析出来赋值给index ,[前面的内容赋值给name
    delim = name.indexOf('[');
    if (delim > -1) {
      index = name.substring(delim + 1, name.length() - 1);
      name = name.substring(0, delim);
    }
  }

  @Override
  public boolean hasNext() {
    return children != null;
  }

  /**
   * 取得下一个,非常简单，直接再通过儿子来new另外一个实例
   * @return PropertyTokenizer
   */
  @Override
  public PropertyTokenizer next() {
    return new PropertyTokenizer(children);
  }

  @Override
  public void remove() {
    throw new UnsupportedOperationException("Remove is not supported, as it has no meaning in the context of properties.");
  }

  @Override
  public Iterator<PropertyTokenizer> iterator() {
    return this;
  }
}
