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
 * 本地缓存机制（Local Cache）防止循环引用（circular references）和加速重复嵌套查询。
 * @author Eduardo Macarron
 */
public enum LocalCacheScope {
  /**
   * 默认值为 session ,缓存一个会话中执行的所有查询
   */
  SESSION,
  /**
   * 若设置值为 statement ，相同 SqlSession 的不同调用将不会共享数据
   */
  STATEMENT
}
