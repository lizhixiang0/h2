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

import java.sql.Connection;

/**
 * 事务隔离级别，是一个枚举型
 * 1.脏读：例子，第一个事物进行到一半的数据被另外一个事物读到，但是第一个事物最后回滚（撤销）了！导致第二个事物读取的数据没有意义！脏读绝对不允许！
 * 2.不可重复读，  例子：一个事物读取两次数据，第一次查询后另外一个事物提交了数据！前后两次读的结果不一致！实际项目允许这种情况的产生！
 * 3.可重复读：相对较完善了，原理，一旦有事物在读取数据，其他任何修改数据的操作无法插手！
 * 4.串行化，  强制所有事物排队！效率差，且容易死锁！锁的整张表，绝对不可取！
 *
 * @author Clinton Begin
 */
public enum TransactionIsolationLevel {
  /**
   * 表示不支持事务
   */
  NONE(Connection.TRANSACTION_NONE),

  /**
   * 读未提交
   * 如果事务连接已经开始写数据，不允许其他事务连接进行写操作,但允许其他事务连接读此行数据。此时可能会导致脏读、不可重复读、幻读
   *
   */
  READ_UNCOMMITTED(Connection.TRANSACTION_READ_UNCOMMITTED),
  /**
   * 读已提交
   * 如果一个事务连接写完数据未提交,禁止其他事务连接访问该行。可能会导致不可重复读、幻读
   *
   */
  READ_COMMITTED(Connection.TRANSACTION_READ_COMMITTED),
  /**
   * 可重复读取
   * 如果一个事务内部有
   *
   */
  REPEATABLE_READ(Connection.TRANSACTION_REPEATABLE_READ),
  /**
   * 序列化
   * 最严格的事务隔离。它要求事务序列化执行，所有事务连接无论读写,只能一个接着一个地执行
   */
  SERIALIZABLE(Connection.TRANSACTION_SERIALIZABLE);

  private final int level;

  TransactionIsolationLevel(int level) {
    this.level = level;
  }

  public int getLevel() {
    return level;
  }
}
