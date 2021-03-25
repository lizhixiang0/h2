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
 * SqlNode接口是动态SQL功能的底层支撑
 * @author Clinton Begin
 */
public interface SqlNode {
  /**
   * 定义不同节点的底层逻辑   "choose、forEach、if、set、where"
   * @param context DynamicContext
   * @return true || false
   */
  boolean apply(DynamicContext context);
}
