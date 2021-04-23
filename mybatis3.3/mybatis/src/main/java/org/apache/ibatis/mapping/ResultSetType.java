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
package org.apache.ibatis.mapping;

import java.sql.ResultSet;

/**
 * 结果集类型
 * 创建使用数据库连接创建Statement的时候可以传递结果集类型,默认是FORWARD_ONLY
 * @author Clinton Begin
 * @description  "https://www.cnblogs.com/catkins/p/5604686.html
 */
public enum ResultSetType {
  /**
   * 默认的
   * The constant indicating the type for a ResultSet object whose cursor may move only forward.
   * 结果集的游标只能向下滚动。
   */
  FORWARD_ONLY(ResultSet.TYPE_FORWARD_ONLY),
  /**
   * The constant indicating the type for a ResultSet object  that is scrollable but generally not sensitive to changes to the data that underlies the ResultSet.
   * 结果集的游标可以上下移动，当数据库变化时，当前结果集不变。
   */
  SCROLL_INSENSITIVE(ResultSet.TYPE_SCROLL_INSENSITIVE),
  /**
   * The constant indicating the type for a ResultSet object that is scrollable and generally sensitive to changes to the data that underlies the ResultSet.
   * 返回可滚动的结果集，当数据库变化时，当前结果集同步改变。
   */
  SCROLL_SENSITIVE(ResultSet.TYPE_SCROLL_SENSITIVE);

  private int value;

  ResultSetType(int value) {
    this.value = value;
  }

  public int getValue() {
    return value;
  }
}
