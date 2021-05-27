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
 *
 * 我低估了这个节点，这个节点是功能最强大的！！！
 SELECT
 <if test="groupByMarket">
 a.market_id AS "marketId",
 a.market_name AS "marketName",
 COUNT( a.id ) AS "scanCount",
 COUNT( DISTINCT a.app_id ) AS "scanApps"
 </if>
 <if test="!groupByMarket">
 a.app_id AS "appId",
 a.app_name AS "appName",
 a.market_id AS "marketId",
 a.version AS "version",
 b.NAME AS "engineName",
 b.charge AS "charge",
 TIMESTAMPDIFF( SECOND, a.scan_start_time, a.scan_end_time ) AS "scanTime",
 a.`status` AS "status",
 JSON_UNQUOTE( JSON_EXTRACT( c.result_summary, '$.score' ) ) AS "score",
 a.operator AS "operator"
 </if>
 FROM
 ac_task a
 <if test="!groupByMarket">
 LEFT JOIN ac_engine b ON a.scan_engine_id = b.id
 LEFT JOIN ac_task_result c ON a.id = c.task_id
 </if>
 <where>
 1=1
 <if test="envCode != null">
 and a.env_code = #{envCode}
 </if>
 <if test="!groupByMarket">
 and a.market_id = #{marketId}
 </if>
 <if test="date != null">
 and date_format( a.task_created_date, '%Y-%m' ) = date_format( #{date}, '%Y-%m' )
 </if>
 <if test="groupByMarket and searchByName != null and searchByName != ''">
 and a.market_name like CONCAT('%',#{searchByName},'%')
 </if>
 <if test="!groupByMarket and searchByName != null and searchByName != ''">
 and a.app_name like CONCAT('%',#{searchByName},'%')
 </if>
 </where>
 <if test="groupByMarket">
 GROUP BY a.market_id,a.market_name
 </if>
 <if test="groupByMarket and orderBy != null and orderBy != ''">
 order by ${orderBy}
 </if>
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
