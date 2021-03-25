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

import java.util.List;

/**
 * choose SQL节点,choose (when,otherwise) ,
 *         相当于java 语言中的 switch,
 *         当 when 中有条件满足的时候，就会跳出 choose，即所有的 when 和 otherwise 条件中，只有一个会输出，
 *         当所有的我很条件都不满足的时候就输出 otherwise 中的内容
 * 例子：
 *         select * from t_blog where 1 = 1
 *         <choose>
 *             <when test="title != null">
 *                 and title = #{title}
 *             </when>
 *             <when test="content != null">
 *                 and content = #{content}
 *             </when>
 *             <otherwise>
 *                 and owner = "owner1"
 *             </otherwise>
 *         </choose>
 *
 * @author Clinton Begin
 */
public class ChooseSqlNode implements SqlNode {
  private SqlNode defaultSqlNode;
  private List<SqlNode> ifSqlNodes;

  public ChooseSqlNode(List<SqlNode> ifSqlNodes, SqlNode defaultSqlNode) {
    this.ifSqlNodes = ifSqlNodes;
    this.defaultSqlNode = defaultSqlNode;
  }


  @Override
  public boolean apply(DynamicContext context) {
    //循环判断if，只要有1个为true了，返回true
    for (SqlNode sqlNode : ifSqlNodes) {
      if (sqlNode.apply(context)) {
        return true;
      }
    }
    //if都不为true，那就看otherwise
    if (defaultSqlNode != null) {
      defaultSqlNode.apply(context);
      return true;
    }
    //如果连otherwise都没有，返回false
    return false;
  }
}
