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

import lombok.Getter;
import lombok.Setter;

/**
 * 作用2个: 分页和 list 查询时控制最多返回数
 * @author Clinton Begin
 * @description limit和offset用法
 * @note   mysql里分页一般用limit来实现
           1. select* from article LIMIT 1,3
           2. select * from article LIMIT 3 OFFSET 1
           上面两种写法都表示取2,3,4三条条数据

          select* from article LIMIT 1,3 就是跳过1条数据,从第2条数据开始取，取3条数据，也就是取2,3,4三条数据
          select * from article LIMIT 3 OFFSET 1 表示跳过1条数据,从第2条数据开始取，取3条数据，也就是取2,3,4三条数据
          select* from article LIMIT 3  表示直接取前三条数据
 */
@Getter
@Setter
public class RowBounds {

  /**
   * 偏移量 ,相当于mysql中的offset
   */
  private int offset;
  /**
   * 界限, 相当于mysql中的limit
   */
  private int limit;

  public static final int NO_ROW_OFFSET = 0;
  public static final int NO_ROW_LIMIT = Integer.MAX_VALUE;
  public static final RowBounds DEFAULT = new RowBounds();

  public RowBounds() {
    //默认是取第一条到第Integer.MAX_VALUE条的所有数据
    this.offset = NO_ROW_OFFSET;
    this.limit = NO_ROW_LIMIT;
  }

  public RowBounds(int offset, int limit) {
    this.offset = offset;
    this.limit = limit;
  }

}
