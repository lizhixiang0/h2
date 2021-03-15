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
 *
 * 1.脏读（针对未提交数据）：如果一个事务中对数据进行了更新，但事务还没有提交，另一个事务可以读到该事务没有提交的更新结果，这样造成的问题就是，如果第一个事务回滚，那么，第二个事务在此之前所读到的数据就是一笔脏数据
 * 2.幻读,幻读是指同样一笔查询在整个事务过程中多次执行中间夹杂这一次update,而这个update是在其他事务执行增删改操作后，则此时前后两次查询是不一致的。
 * 3.不可重复读，如果事务1在事务2的更新操作之前读取一次数据，在事务2的更新操作之后再读取同一笔数据一次，两次内容是不同的
 * 4.可重复读：相对较完善了，原理，一旦有事物在读取数据，其他任何修改数据的操作无法插手！
 * 5.串行化，  强制所有事物排队！效率差，且容易死锁！锁的整张表，绝对不可取！
 *
 *
 * https://blog.csdn.net/MarkusZhang/article/details/107335259
 * 当前读:select...lock in share mode; select...for update;
 * 当前读:update、insert、delete
 * 快照读:不加锁的非阻塞读，select
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
   * 读已提交,俗称RC级别
   * 如果一个事务连接写完数据未提交,禁止其他事务连接访问该行。看起来很严格，但是也会可能会导致不可重复读、幻读
   *
   */
  READ_COMMITTED(Connection.TRANSACTION_READ_COMMITTED),
  /**
   * 可重复读取,俗称RR级别
   * 如果一个事务正在读取内容，其他事务不允许对当前内容进行写操作。无法避免幻读
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
