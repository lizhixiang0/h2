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
 * 结果处理器
 * StatementHandler在处理查询结果的时候,会调用ResultSetHandler对查询结果处理,所以说,只有select方法才有ResultHandler参数
 * @author Clinton Begin
 * @note 有一种场景，导出文件100万条数据，如果直接mybatis把整个数据查询到list中。那么，就有一个问题，如果数据量大的话，就会导致大对象，内存溢出（OOM）。
 *       这个时候我们就可以利用Mybatis中的ResultHandler来处理。
 */

public interface ResultHandler {

  /**
   * 处理结果
   * 为什么会传递一个ResultContext？
   */
  void handleResult(ResultContext context);

}
