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
package org.apache.ibatis.session;

/**
 * 指定 MyBatis 应如何自动映射列到字段或属性
 *
 * @author Eduardo Macarron
 */
public enum AutoMappingBehavior {

  /**
   * NONE 表示取消自动映射
   *    意思就是映射文件中，对于resultMap标签，如果没有显式定义result标签，mybatis不会把结果映射到model(pojo)上.
   *     <resultMap id="orderModelMap1" type="com.javacode2018.chat05.demo7.model.OrderModel">
   *       <id column="id" property="id"/>
   *       <result column="userId" property="userId" />
   *       <result column="createTime" property="createTime" />
   *       <result column="upTime" property="upTime" />
   *     </resultMap>
   */
  NONE,

  /**
   * PARTIAL 只会自动映射没有定义嵌套结果集映射的结果集
   * 意思就是映射文件中，对于resultMap标签，显式定义result标签，mybatis会把结果映射到model(pojo)上.
   * 但是有些复杂的查询映射会在resultMap中嵌套一些映射（如：association，collection）
   * 当使用PARTIAL的时候，如果有嵌套映射，则这个嵌套映射不会进行自动映射了
   * <resultMap id="orderModelMap6" type="com.javacode2018.chat05.demo7.model.OrderModel">
   *      <association property="userModel"></association>
   * </resultMap>

   * <select id="getById6" resultMap="orderModelMap6">
   *   <![CDATA[
   *   SELECT
   *     a.id,
   *     a.user_id userId,
   *     b.id as user_id,
   *     b.name
   *   FROM
   *     t_order a,t_user b
   *   WHERE
   *     a.user_id = b.id
   *   AND a.id = #{value}
   * ]]>
   </select>

   public class OrderModel {
      private Integer id;
      private Integer userId;
      private UserModel userModel;
   }

   public class UserModel {
      private Integer id;
      private String name;
   }

   */
  PARTIAL,

  /**
   * 会自动映射任意复杂的结果集（无论是否嵌套）
   * 自动映射所有属性
   */
  FULL
}
