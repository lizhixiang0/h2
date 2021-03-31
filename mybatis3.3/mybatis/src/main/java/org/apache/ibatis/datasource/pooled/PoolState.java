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
package org.apache.ibatis.datasource.pooled;

import java.util.ArrayList;
import java.util.List;

/**
 * 连接池状态,操作数据的方法都是同步方法
 * @author Clinton Begin
 */
public class PoolState {
  /**
   * 连接池
   */
  protected PooledDataSource dataSource;
  /**
   * 空闲连接
   */
  protected final List<PooledConnection> idleConnections = new ArrayList<>();
  /**
   * 活动连接
   */
  protected final List<PooledConnection> activeConnections = new ArrayList<>();

  //----------以下是一些统计信息----------
  /**
   * 请求获取连接的次数
   */
  protected long requestCount = 0;
  /**
   * 累计请求时间
   */
  protected long accumulatedRequestTime = 0;
  /**
   * 累计活动连接的活动时长
   */
  protected long accumulatedCheckoutTime = 0;
  /**
   * 已声明的过期连接数
   */
  protected long claimedOverdueConnectionCount = 0;
  /**
   * 累计过期连接的检验总时长
   */
  protected long accumulatedCheckoutTimeOfOverdueConnections = 0;
  /**
   * 累计等待时间
   */
  protected long accumulatedWaitTime = 0;
  /**
   * 请求获取连接等待的次数 (一次请求只计算一次)
   */
  protected long hadToWaitCount = 0;
  /**
   * 坏的连接次数（指拿到了连接,但是valid=false）
   */
  protected long badConnectionCount = 0;

  public PoolState(PooledDataSource dataSource) {
    this.dataSource = dataSource;
  }

  /**
   * 获取请求时间平均值
   */
  public synchronized long getAverageRequestTime() {
    // 类计请求时间/请求次数
    return requestCount == 0 ? 0 : accumulatedRequestTime / requestCount;
  }

  /**
   * 获取等待时间平均值
   */
  public synchronized long getAverageWaitTime() {
    // 累计等待时间/不得不等待的数量
    return hadToWaitCount == 0 ? 0 : accumulatedWaitTime / hadToWaitCount;

  }

  /**
   * 获得过期检测时间平均值
   */
  public synchronized long getAverageOverdueCheckoutTime() {
    // 累计过期连接的检验时间/已声明的过期连接数
    return claimedOverdueConnectionCount == 0 ? 0 : accumulatedCheckoutTimeOfOverdueConnections / claimedOverdueConnectionCount;
  }

  /**
   * 获得检验时间平均值
   */
  public synchronized long getAverageCheckoutTime() {
    // 累计检验时间/请求次数
    return requestCount == 0 ? 0 : accumulatedCheckoutTime / requestCount;
  }

  public synchronized long getRequestCount() {
    return requestCount;
  }

  public synchronized long getHadToWaitCount() {
    return hadToWaitCount;
  }

  public synchronized long getBadConnectionCount() {
    return badConnectionCount;
  }

  public synchronized long getClaimedOverdueConnectionCount() {
    return claimedOverdueConnectionCount;
  }
  public synchronized int getIdleConnectionCount() {
    return idleConnections.size();
  }

  public synchronized int getActiveConnectionCount() {
    return activeConnections.size();
  }

  //打印统计信息，可以供性能优化用
  @Override
  public synchronized String toString() {
    return "\n===CONFINGURATION==============================================" +
            "\n jdbcDriver                     " + dataSource.getDriver() +
            "\n jdbcUrl                        " + dataSource.getUrl() +
            "\n jdbcUsername                   " + dataSource.getUsername() +
            "\n jdbcPassword                   " + (dataSource.getPassword() == null ? "NULL" : "************") +
            "\n poolMaxActiveConnections       " + dataSource.poolMaximumActiveConnections +
            "\n poolMaxIdleConnections         " + dataSource.poolMaximumIdleConnections +
            "\n poolMaxCheckoutTime            " + dataSource.poolMaximumCheckoutTime +
            "\n poolTimeToWait                 " + dataSource.poolTimeToWait +
            "\n poolPingEnabled                " + dataSource.poolPingEnabled +
            "\n poolPingQuery                  " + dataSource.poolPingQuery +
            "\n poolPingConnectionsNotUsedFor  " + dataSource.poolPingConnectionsNotUsedFor +
            "\n ---STATUS-----------------------------------------------------" +
            "\n activeConnections              " + getActiveConnectionCount() +
            "\n idleConnections                " + getIdleConnectionCount() +
            "\n requestCount                   " + getRequestCount() +
            "\n averageRequestTime             " + getAverageRequestTime() +
            "\n averageCheckoutTime            " + getAverageCheckoutTime() +
            "\n claimedOverdue                 " + getClaimedOverdueConnectionCount() +
            "\n averageOverdueCheckoutTime     " + getAverageOverdueCheckoutTime() +
            "\n hadToWait                      " + getHadToWaitCount() +
            "\n averageWaitTime                " + getAverageWaitTime() +
            "\n badConnectionCount             " + getBadConnectionCount() +
            "\n===============================================================";
  }

}
