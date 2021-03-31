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

import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.apache.ibatis.datasource.unpooled.UnpooledDataSource;
import org.apache.ibatis.logging.Log;
import org.apache.ibatis.logging.LogFactory;

/**
 * 池化数据源,这个是mybatis自己实现的连接池,其他还有诸如C3P0、DBCP、Druid等等
 * This is a simple, synchronous, thread-safe database connection pool.
 * @author Clinton Begin
 */
public class PooledDataSource implements DataSource {

  private static final Log log = LogFactory.getLog(PooledDataSource.class);

  private final UnpooledDataSource dataSource;

  /**
   * 将连接池状态剥离出去,构建了一个PoolState
   */
  private final PoolState state = new PoolState(this);
  /**
   * 最大连接数,包括活动连接和空闲连接
   */
  protected int poolMaximumActiveConnections = 10;
  /**
   * 最大空闲连接数
   */
  protected int poolMaximumIdleConnections = 5;
  /**
   * 活动连接最大活动时间
   */
  protected int poolMaximumCheckoutTime = 20000;
  /**
   * 连接池等待时长,此时已经达到了最大连接数，且都是活动连接！并且最老的那个连接还为达到最大活动时间！所以连接只能等！这个值必须大于等于活动连接的最大活动时间！
   */
  protected int poolTimeToWait = 20000;
  /**
   * 发送到数据的侦测查询,用来验证连接是否能ping通。默认是"NO PING QUERY SET",必须自己用一个合法的SQL语句（最好是很快速的）比如SELECT 'x' FROM DUAL
   */
  protected String poolPingQuery = "NO PING QUERY SET";
  /**
   * 开启或禁用侦测查询,就是让不让ping
   */
  protected boolean poolPingEnabled = false;
  /**
   * 用来配置 poolPingQuery ，就是该连接必须上次使用到当前的时间必须大于这个值才允许ping,避免不必要的侦测
   */
  protected int poolPingConnectionsNotUsedFor = 0;
  /**
   * 根据url、username、password生成的标识
   */
  private int expectedConnectionTypeCode;

  /**
   * 无参构造
   */
  public PooledDataSource() {
    // 数据源初始化,这里可以看到 PooledDataSource实际上应该是对UnpooledDataSource的包装
    dataSource = new UnpooledDataSource();
  }

  public PooledDataSource(String driver, String url, String username, String password) {
    dataSource = new UnpooledDataSource(driver, url, username, password);
    expectedConnectionTypeCode = assembleConnectionTypeCode(dataSource.getUrl(), dataSource.getUsername(), dataSource.getPassword());
  }

  public PooledDataSource(String driver, String url, Properties driverProperties) {
    dataSource = new UnpooledDataSource(driver, url, driverProperties);
    expectedConnectionTypeCode = assembleConnectionTypeCode(dataSource.getUrl(), dataSource.getUsername(), dataSource.getPassword());
  }

  public PooledDataSource(ClassLoader driverClassLoader, String driver, String url, String username, String password) {
    dataSource = new UnpooledDataSource(driverClassLoader, driver, url, username, password);
    expectedConnectionTypeCode = assembleConnectionTypeCode(dataSource.getUrl(), dataSource.getUsername(), dataSource.getPassword());
  }

  public PooledDataSource(ClassLoader driverClassLoader, String driver, String url, Properties driverProperties) {
    dataSource = new UnpooledDataSource(driverClassLoader, driver, url, driverProperties);
    expectedConnectionTypeCode = assembleConnectionTypeCode(dataSource.getUrl(), dataSource.getUsername(), dataSource.getPassword());
  }

  /**
   * 将url、username、password拼接后进行哈希
   * @param url url
   * @param username username
   * @param password password
   * @return int
   */
  private int assembleConnectionTypeCode(String url, String username, String password) {
    return ("" + url + username + password).hashCode();
  }

  /**
   * 覆盖了DataSource.getConnection方法，每次都是pop一个Connection，即从池中取出一个来
   */
  @Override
  public Connection getConnection() throws SQLException {
    return popConnection(dataSource.getUsername(), dataSource.getPassword()).getProxyConnection();
  }

  @Override
  public Connection getConnection(String username, String password) throws SQLException {
    return popConnection(username, password).getProxyConnection();
  }

  @Override
  public void setLoginTimeout(int loginTimeout) {
    DriverManager.setLoginTimeout(loginTimeout);
  }

  @Override
  public int getLoginTimeout() {
    return DriverManager.getLoginTimeout();
  }

  @Override
  public void setLogWriter(PrintWriter logWriter) {
    DriverManager.setLogWriter(logWriter);
  }

  @Override
  public PrintWriter getLogWriter() {
    return DriverManager.getLogWriter();
  }

  public void setDriver(String driver) {
    dataSource.setDriver(driver);
    forceCloseAll();
  }

  public void setUrl(String url) {
    dataSource.setUrl(url);
    forceCloseAll();
  }

  public void setUsername(String username) {
    dataSource.setUsername(username);
    forceCloseAll();
  }

  public void setPassword(String password) {
    dataSource.setPassword(password);
    forceCloseAll();
  }

  public void setDefaultAutoCommit(boolean defaultAutoCommit) {
    dataSource.setAutoCommit(defaultAutoCommit);
    forceCloseAll();
  }

  public void setDefaultTransactionIsolationLevel(Integer defaultTransactionIsolationLevel) {
    dataSource.setDefaultTransactionIsolationLevel(defaultTransactionIsolationLevel);
    forceCloseAll();
  }

  public void setDriverProperties(Properties driverProps) {
    dataSource.setDriverProperties(driverProps);
    forceCloseAll();
  }

  /*
   * 最大活动连接数
   */
  public void setPoolMaximumActiveConnections(int poolMaximumActiveConnections) {
    this.poolMaximumActiveConnections = poolMaximumActiveConnections;
    forceCloseAll();
  }

  /*
   * 最大空闲连接数
   */
  public void setPoolMaximumIdleConnections(int poolMaximumIdleConnections) {
    this.poolMaximumIdleConnections = poolMaximumIdleConnections;
    forceCloseAll();
  }

  /*
   * 重试连接之前等待的时间
   */
  public void setPoolMaximumCheckoutTime(int poolMaximumCheckoutTime) {
    this.poolMaximumCheckoutTime = poolMaximumCheckoutTime;
    forceCloseAll();
  }

  /*
   * 重试连接之前等待的时间
   *
   * @param poolTimeToWait The time to wait
   */
  public void setPoolTimeToWait(int poolTimeToWait) {
    this.poolTimeToWait = poolTimeToWait;
    forceCloseAll();
  }

  /*
   * 用于检查连接的查询
   */
  public void setPoolPingQuery(String poolPingQuery) {
    this.poolPingQuery = poolPingQuery;
    forceCloseAll();
  }

  /*
   * 设置是否使用ping查询
   */
  public void setPoolPingEnabled(boolean poolPingEnabled) {
    this.poolPingEnabled = poolPingEnabled;
    forceCloseAll();
  }

  /*
   * 如果一个连接在某毫秒内没有被使用，ping数据库，以确保连接仍然良好。
   */
  public void setPoolPingConnectionsNotUsedFor(int milliseconds) {
    this.poolPingConnectionsNotUsedFor = milliseconds;
    forceCloseAll();
  }

  public String getDriver() {
    return dataSource.getDriver();
  }

  public String getUrl() {
    return dataSource.getUrl();
  }

  public String getUsername() {
    return dataSource.getUsername();
  }

  public String getPassword() {
    return dataSource.getPassword();
  }

  public boolean isAutoCommit() {
    return dataSource.isAutoCommit();
  }

  public Integer getDefaultTransactionIsolationLevel() {
    return dataSource.getDefaultTransactionIsolationLevel();
  }

  public Properties getDriverProperties() {
    return dataSource.getDriverProperties();
  }

  public int getPoolMaximumActiveConnections() {
    return poolMaximumActiveConnections;
  }

  public int getPoolMaximumIdleConnections() {
    return poolMaximumIdleConnections;
  }

  public int getPoolMaximumCheckoutTime() {
    return poolMaximumCheckoutTime;
  }

  public int getPoolTimeToWait() {
    return poolTimeToWait;
  }

  public String getPoolPingQuery() {
    return poolPingQuery;
  }

  public boolean isPoolPingEnabled() {
    return poolPingEnabled;
  }

  public int getPoolPingConnectionsNotUsedFor() {
    return poolPingConnectionsNotUsedFor;
  }

  public PoolState getPoolState() {
    return state;
  }

  /*
   * 关闭池中的所有活动连接和空闲连接
   */
  public void forceCloseAll() {
    // 同步锁
    synchronized (state) {
      // 1、获得连接哈希值
      expectedConnectionTypeCode = assembleConnectionTypeCode(dataSource.getUrl(), dataSource.getUsername(), dataSource.getPassword());
      // 2、遍历关闭所有的活动连接
      for (int i = state.activeConnections.size(); i > 0; i--) {
        try {
          // 2.1、先把activeConnections容器中的连接remove ,这里是从后往前删？
          PooledConnection conn = state.activeConnections.remove(i - 1);
          // 2.2、连接设为失效
          conn.invalidate();
          // 2.3、获取真实连接
          Connection realConn = conn.getRealConnection();
          // 2.4、如果不是自动提交,回滚未提交的内容
          if (!realConn.getAutoCommit()) {
            realConn.rollback();
          }
          // 2.5、关闭连接  ,这个是真的断开连接了
          realConn.close();
        } catch (Exception ignored) {
        }
      }
      // 3、遍历关闭所有的空闲连接
      for (int i = state.idleConnections.size(); i > 0; i--) {
        try {
          PooledConnection conn = state.idleConnections.remove(i - 1);
          conn.invalidate();

          Connection realConn = conn.getRealConnection();
          if (!realConn.getAutoCommit()) {
            realConn.rollback();
          }
          realConn.close();
        } catch (Exception ignored) {
        }
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("PooledDataSource forcefully closed/removed all connections.");
    }
  }

  /**
   * 获取连接,最不理想的情况下会等待20s
   */
  private PooledConnection popConnection(String username, String password) throws SQLException {
    // 辅助等待计数
    boolean countedWait = false;
    PooledConnection conn = null;
    // 用来计算获取连接一共花了多少时间
    long t = System.currentTimeMillis();
    // 获取不可用连接的次数，如果多次获得的连接都不可用就抛出异常
    int localBadConnectionCount = 0;

    //最外面是while死循环，如果一直拿不到connection，则不断尝试
    while (conn == null) {
      synchronized (state) {
        // 1、判断是否有空闲的连接，如果有,取出第一个,并将其从空闲列表中删除
        if (!state.idleConnections.isEmpty()) {
          conn = state.idleConnections.remove(0);
          if (log.isDebugEnabled()) {
            log.debug("Checked out connection " + conn.getRealHashCode() + " from pool.");
          }
        } else {
          // 2、如果没有空闲的连接，判断活动连接数量是否小于最大连接数，小于则表示还可以创建,那就创建一个
          if (state.activeConnections.size() < poolMaximumActiveConnections) {
            conn = new PooledConnection(dataSource.getConnection(), this);
            if (log.isDebugEnabled()) {
              log.debug("Created connection " + conn.getRealHashCode() + ".");
            }
          } else {
        	//2.1、如果activeConnections已经很多了，那不能再new了，取得activeConnections列表的第一个（最老的）
            PooledConnection oldestActiveConnection = state.activeConnections.get(0);
            // 获取该连接的活动时间
            long longestCheckoutTime = oldestActiveConnection.getCheckoutTime();
            // 2.2、如果其活动时间大于连接池规定的最大活动时间，强制使其过期
            if (longestCheckoutTime > poolMaximumCheckoutTime){
              // 过期连接数+1
              state.claimedOverdueConnectionCount++;
              // 累计过期连接检测总时长+=当前连接的活动时长
              state.accumulatedCheckoutTimeOfOverdueConnections += longestCheckoutTime;
              // 累计活动总时长+=当前连接的活动时长
              state.accumulatedCheckoutTime += longestCheckoutTime;
              // 将该连接从活动连接列表里删除
              state.activeConnections.remove(oldestActiveConnection);
              // 将该连接回滚
              if (!oldestActiveConnection.getRealConnection().getAutoCommit()) {
                oldestActiveConnection.getRealConnection().rollback();
              }
              // 将该连接设置为失效
              oldestActiveConnection.invalidate();
              // 取出该连接的真实连接,然后重新创建一个PooledConnection赋值给conn
              conn = new PooledConnection(oldestActiveConnection.getRealConnection(), this);
              if (log.isDebugEnabled()) {
                log.debug("Claimed overdue connection " + conn.getRealHashCode() + ".");
              }
            // 2.3、如果该连接的活动时间小于连接池规定的最大活动时间，等待吧
            } else {
              try {
                if (!countedWait) {
                  //统计信息：等待+1
                  state.hadToWaitCount++;
                  // 如果第一次就是这样,此时置为true,那下一次咋搞？是否可以理解为，一次请求过来拿连接,不管他在while循环里循环多少次,只计算它等待了一次！
                  countedWait = true;
                }
                if (log.isDebugEnabled()) {
                  log.debug("Waiting as long as " + poolTimeToWait + " milliseconds for connection.");
                }
                // 记录当前时间戳
                long wt = System.currentTimeMillis();
                // 当前线程进入等待状态,指定等待时间为poolTimeToWait
                state.wait(poolTimeToWait);
                // 等完候,计算等待时间,将等待时间累加到accumulatedWaitTime
                state.accumulatedWaitTime += System.currentTimeMillis() - wt;
                // 此时等待了一波，这波时间内任何人来拿连接都是拿不到的!但是等完后会有大部分甚至全部（看等了多久）的活动连接活动时间到期,所以下一波会拿到连接（这里还是有问题，因为不能保证是这次的请求拿到连接）
              } catch (InterruptedException e) {
                // 出现异常就break跳出while循环，此时conn为null ,这是唯一主动跳出循环的地方,出去之后还是会抛出异常，应该也可以直接在这里抛出异常，但是作者选择这里跳出，出去抛，可能是不想污染代码。
                break;
              }
            }
          }
        }
        // 3、上面两步尝试从空闲连接和活动连接中取,不一定能拿到
        if (conn != null) {
        	// 3.1、如果已经拿到connection，查看连接是否可用,可用的话回滚未提交的数据，然后进行一系列的设置
          if (conn.isValid()) {
            if (!conn.getRealConnection().getAutoCommit()) {
              conn.getRealConnection().rollback();
            }
            // 设置连接的信息hash码
            conn.setConnectionTypeCode(assembleConnectionTypeCode(dataSource.getUrl(), username, password));
            // 设置连接的迁出时间为当前时间
            conn.setCheckoutTimestamp(System.currentTimeMillis());
            // 设置连接的最后使用时间为当前时间
            conn.setLastUsedTimestamp(System.currentTimeMillis());
            // 将其添加到活动连接列表中去
            state.activeConnections.add(conn);
            // 请求获取连接的次数+1
            state.requestCount++;
            // 请求的时间累计到accumulatedRequestTime
            state.accumulatedRequestTime += System.currentTimeMillis() - t;
          } else {
            if (log.isDebugEnabled()) {
              log.debug("A bad connection (" + conn.getRealHashCode() + ") was returned from the pool, getting another connection.");
            }
            // 3.2、如果该连接不可用,设置统计信息
            // 不可用连接+1
            state.badConnectionCount++;
            // 获取不可用连接的次数+1
            localBadConnectionCount++;
            conn = null;
            if (localBadConnectionCount > (poolMaximumIdleConnections + 3)) {
            	//如果好几次拿到的连接都是invalid,抛出异常  （最大次数是空闲连接+3 ？？）
              if (log.isDebugEnabled()) {
                log.debug("PooledDataSource: Could not get a good connection to the database.");
              }
              throw new SQLException("PooledDataSource: Could not get a good connection to the database.");
            }
          }
        }
        // 如果coon为null ，继续下一次的循环
      }

    }

    if (conn == null) {
      if (log.isDebugEnabled()) {
        log.debug("PooledDataSource: Unknown severe error condition.  The connection pool returned a null connection.");
      }
      throw new SQLException("PooledDataSource: Unknown severe error condition.  The connection pool returned a null connection.");
    }

    return conn;
  }

  /**
   * 当用户使用完连接想要调用close关闭连接时会触发此方法。
   * 将活动连接转为空闲连接，或者关闭该连接
   */
  protected void pushConnection(PooledConnection conn) throws SQLException {
    // 同步锁
    synchronized (state) {
      // 1、先从activeConnections中删除此connection
      state.activeConnections.remove(conn);
      // 2、判断此连接是否可用
      if (conn.isValid()) {
        // 2.1、如果空闲连接数小于最大空闲连接且是同类连接，则将该连接转为空闲连接
        if (state.idleConnections.size() < poolMaximumIdleConnections && conn.getConnectionTypeCode() == expectedConnectionTypeCode) {
          // a、累计活动时间
          state.accumulatedCheckoutTime += conn.getCheckoutTime();
          // b、回滚
          if (!conn.getRealConnection().getAutoCommit()) {
            conn.getRealConnection().rollback();
          }
          // c、new一个新的Connection，加入到idle列表
          PooledConnection newConn = new PooledConnection(conn.getRealConnection(), this);
          // d、新增空闲连接
          state.idleConnections.add(newConn);
          // e、设置老的创建时间拿过来塞进去
          newConn.setCreatedTimestamp(conn.getCreatedTimestamp());
          // f、老的最后使用时间塞进去
          newConn.setLastUsedTimestamp(conn.getLastUsedTimestamp());
          // g、将老的连接设置为不可用
          conn.invalidate();
          if (log.isDebugEnabled()) {
            log.debug("Returned connection " + newConn.getRealHashCode() + " to pool.");
          }
          // h、通知其他线程可以来抢connection了 （唤醒所有调用wait方法而等待的线程）
          state.notifyAll();
        } else {
          // 2.2、否则，关闭该链接
          state.accumulatedCheckoutTime += conn.getCheckoutTime();
          // a、回滚
          if (!conn.getRealConnection().getAutoCommit()) {
            conn.getRealConnection().rollback();
          }
          // b、那就将connection关闭就可以了
          conn.getRealConnection().close();
          if (log.isDebugEnabled()) {
            log.debug("Closed connection " + conn.getRealHashCode() + ".");
          }
          // c、关闭后将该连接设为不可用
          conn.invalidate();
        }
      } else {
        if (log.isDebugEnabled()) {
          log.debug("A bad connection (" + conn.getRealHashCode() + ") attempted to return to the pool, discarding connection.");
        }
        // 3、不可用连接+1
        state.badConnectionCount++;
      }
    }
  }

  /**
   * 检查连接是否仍然可用
   */
  protected boolean pingConnection(PooledConnection conn) {
    boolean result;
    try {
      // 1、取的连接的状态，如果是已关闭,那肯定ping不通。result设为false
      result = !conn.getRealConnection().isClosed();
    } catch (SQLException e) {
      if (log.isDebugEnabled()) {
        log.debug("Connection " + conn.getRealHashCode() + " is BAD: " + e.getMessage());
      }
      result = false;
    }
    // 2、那如果是未关闭状态，则result为true，此时尝试ping它
    if (result) {
      // 2.1、没有开启侦探允许,不许ping
      if (poolPingEnabled) {
        // 2.1.1、如果设置了poolPingConnectionsNotUsedFor参数，并且该连接自上次使用以来经过的时间大于这个值,那就允许ping
        if (poolPingConnectionsNotUsedFor >= 0 && conn.getTimeElapsedSinceLastUse() > poolPingConnectionsNotUsedFor) {
          try {
            if (log.isDebugEnabled()) {
              log.debug("Testing connection " + conn.getRealHashCode() + " ...");
            }
            // a、获取真实连接
            Connection realConn = conn.getRealConnection();
            // b、创建Statement （sql）
            Statement statement = realConn.createStatement();
            // c、传递参数
            ResultSet rs = statement.executeQuery(poolPingQuery);
            // d、关闭rs和statement
            rs.close();
            statement.close();
            // e、回滚
            if (!realConn.getAutoCommit()) {
              realConn.rollback();
            }
            // f、result设置为true
            result = true;
            if (log.isDebugEnabled()) {
              log.debug("Connection " + conn.getRealHashCode() + " is GOOD!");
            }
          } catch (Exception e) {
            log.warn("Execution of ping query '" + poolPingQuery + "' failed: " + e.getMessage());
            try {
              conn.getRealConnection().close();
            } catch (Exception e2) {
              //ignore
            }
            result = false;
            if (log.isDebugEnabled()) {
              log.debug("Connection " + conn.getRealHashCode() + " is BAD: " + e.getMessage());
            }
          }
        }
      }
    }
    return result;
  }

  /**
   * 打开一个池连接以获得真实连接
   */
  public static Connection unwrapConnection(Connection conn) {
    if (Proxy.isProxyClass(conn.getClass())) {
      InvocationHandler handler = Proxy.getInvocationHandler(conn);
      if (handler instanceof PooledConnection) {
        return ((PooledConnection) handler).getRealConnection();
      }
    }
    return conn;
  }

  /**
   *  这个方法在对象被回收时由JVM调用
   */
  @Override
  protected void finalize() throws Throwable {
    // 该池对象被回收时,会断开所有的数据库连接
    forceCloseAll();
    super.finalize();
  }

  @Override
  public <T> T unwrap(Class<T> iface) throws SQLException {
    throw new SQLException(getClass().getName() + " is not a wrapper.");
  }

  @Override
  public boolean isWrapperFor(Class<?> iface) {
    return false;
  }

  @Override
  public Logger getParentLogger() {
    return Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
  }

}
