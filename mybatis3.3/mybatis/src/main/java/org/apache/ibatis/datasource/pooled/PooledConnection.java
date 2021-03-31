/*
 *    Copyright 2009-2014 the original author or authors.
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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;

import org.apache.ibatis.reflection.ExceptionUtil;

/**
 * 池化连接 ,相当于真实连接的代理
 * @author Clinton Begin
 */
class PooledConnection implements InvocationHandler {
  /**
   * 代表connection的close方法
   */
  private static final String CLOSE = "close";
  /**
   * 代理类要实现的接口列表
   */
  private static final Class<?>[] IFACES = new Class<?>[] { Connection.class };

  /**
   * 该连接的hash值
   */
  private int hashCode = 0;
  /**
   * 池化数据源
   */
  private PooledDataSource dataSource;
  /**
   * 真实连接
   */
  private Connection realConnection;
  /**
   * 代理连接
   */
  private Connection proxyConnection;
  /**
   * 签出时间
   */
  private long checkoutTimestamp;
  /**
   * 刚创建PooledConnection的时间戳
   */
  private long createdTimestamp;
  /**
   * 最后一次使用的时间戳
   */
  private long lastUsedTimestamp;
  /**
   * 连接信息的哈希值
   */
  private int connectionTypeCode;
  /**
   * 连接是否有效
   */
  private boolean valid;

  /**
   * 无参构造
   * @param connection connection
   * @param dataSource PooledDataSource
   */
  public PooledConnection(Connection connection, PooledDataSource dataSource) {
    this.hashCode = connection.hashCode();
    this.realConnection = connection;
    this.dataSource = dataSource;
    this.createdTimestamp = System.currentTimeMillis();
    // 为啥在这里初始化？？
    this.lastUsedTimestamp = System.currentTimeMillis();
    this.valid = true;
    // 初始化代理连接
    this.proxyConnection = (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), IFACES, this);
  }

  /**
   * 使连接无效
   */
  public void invalidate() {
    valid = false;
  }

  /**
   * 方法查看连接是否可用
   */
  public boolean isValid() {
    return valid && realConnection != null && dataSource.pingConnection(this);
  }

  /**
   * 获取实际连接
   */
  public Connection getRealConnection() {
    return realConnection;
  }

  /**
   * 获取代理连接
   */
  public Connection getProxyConnection() {
    return proxyConnection;
  }

  /**
   * 获取实际连接的hashcode(如果为null，则为0)
   */
  public int getRealHashCode() {
    return realConnection == null ? 0 : realConnection.hashCode();
  }

  /**
   * 获取连接类型哈希值(基于url +用户+密码)
   */
  public int getConnectionTypeCode() {
    return connectionTypeCode;
  }

  /**
   * 设置连接类型哈希值(基于url +用户+密码)
   */
  public void setConnectionTypeCode(int connectionTypeCode) {
    this.connectionTypeCode = connectionTypeCode;
  }

  /**
   * 获取刚创建PooledConnection的时间戳
   */
  public long getCreatedTimestamp() {
    return createdTimestamp;
  }

  /**
   * 设置刚创建PooledConnection的时间戳
   */
  public void setCreatedTimestamp(long createdTimestamp) {
    this.createdTimestamp = createdTimestamp;
  }

  /**
   * 获取最后一次使用的时间戳
   */
  public long getLastUsedTimestamp() {
    return lastUsedTimestamp;
  }

  /**
   * 设置连接最后一次使用的时间戳
   */
  public void setLastUsedTimestamp(long lastUsedTimestamp) {
    this.lastUsedTimestamp = lastUsedTimestamp;
  }

  /**
   * 获取自上次使用以来经过的时间
   */
  public long getTimeElapsedSinceLastUse() {
    return System.currentTimeMillis() - lastUsedTimestamp;
  }

  /**
   * 获取连接的时长
   */
  public long getAge() {
    return System.currentTimeMillis() - createdTimestamp;
  }

  /**
   * 获取连接签出的时间戳
   */
  public long getCheckoutTimestamp() {
    return checkoutTimestamp;
  }

  /**
   * 设置连接签出的时间戳
   */
  public void setCheckoutTimestamp(long timestamp) {
    this.checkoutTimestamp = timestamp;
  }

  /**
   * 获取该连接签出距今的时间，可以理解成一个连接的最大活动时间
   */
  public long getCheckoutTime() {
    return System.currentTimeMillis() - checkoutTimestamp;
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * 允许连接间互相比较
   */
  @Override
  public boolean equals(Object obj) {
    if (obj instanceof PooledConnection) {
      // 取出真实连接进行hash
      return realConnection.hashCode() == (((PooledConnection) obj).realConnection.hashCode());
    } else if (obj instanceof Connection) {
      return hashCode == obj.hashCode();
    } else {
      return false;
    }
  }

  /**
   * 代理连接的所有方法！就是通过这个来控制连接的关闭
   */
  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    // 1、获取方法名
    String methodName = method.getName();
    // 2、如果调用的close方法,不执行
    if (CLOSE.hashCode() == methodName.hashCode() && CLOSE.equals(methodName)) {
      // 2.1 而是将这个connection加入到池中
      dataSource.pushConnection(this);
      return null;
    } else {
      // 3、如果不是调用的close方法，
      try {
        // 3.1、该方法是否继承自Object,例如clone、toString、。。
        if (!Object.class.equals(method.getDeclaringClass())) {
          // 3.1.1、如果是Connection自己声明的方法,调用之前要检查connection是否有效，无效抛出异常
          checkConnection();
        }
        // 3.2、交给真正的connection去执行
        return method.invoke(realConnection, args);
      } catch (Throwable t) {
        throw ExceptionUtil.unwrapThrowable(t);
      }
    }
  }

  private void checkConnection() throws SQLException {
    if (!valid) {
      throw new SQLException("Error accessing PooledConnection. Connection is invalid.");
    }
  }

}
