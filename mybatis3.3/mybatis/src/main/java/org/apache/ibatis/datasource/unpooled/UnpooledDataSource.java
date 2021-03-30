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
package org.apache.ibatis.datasource.unpooled;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import javax.sql.DataSource;

import lombok.Getter;
import lombok.Setter;
import org.apache.ibatis.io.Resources;

/**
 * 没有池化的数据源
 * @author Clinton Begin
 * @author Eduardo Macarron
 */
@Getter
@Setter
public class UnpooledDataSource implements DataSource {
  /**
   * 驱动类加载器
   */
  private ClassLoader driverClassLoader;

  /**
   *存放属性的前缀是以"driver."开头的 例如：driver.encoding=UTF8
   */
  private Properties driverProperties;
  /**
   * 注册驱动的容器,ConcurrentHashMap ?
   */
  private static Map<String, Driver> registeredDrivers = new ConcurrentHashMap<>();

  private String driver;
  private String url;
  private String username;
  private String password;

  private Boolean autoCommit;
  private Integer defaultTransactionIsolationLevel;

  static {
    // 1、获取JDBC驱动程序(Enumeration与迭代器类似,如果之前加载过数据库驱动，那这里就能获取到)
    Enumeration<Driver> drivers = DriverManager.getDrivers();
    while (drivers.hasMoreElements()) {
      Driver driver = drivers.nextElement();
      // 2、注册进驱动容器里
      registeredDrivers.put(driver.getClass().getName(), driver);
    }
  }

  /**
   * 无参构造、工厂里是调用这个创建数据源的。
   */
  public UnpooledDataSource() {
  }

  public UnpooledDataSource(String driver, String url, String username, String password) {
    this.driver = driver;
    this.url = url;
    this.username = username;
    this.password = password;
  }

  public UnpooledDataSource(String driver, String url, Properties driverProperties) {
    this.driver = driver;
    this.url = url;
    this.driverProperties = driverProperties;
  }

  public UnpooledDataSource(ClassLoader driverClassLoader, String driver, String url, String username, String password) {
    this.driverClassLoader = driverClassLoader;
    this.driver = driver;
    this.url = url;
    this.username = username;
    this.password = password;
  }

  public UnpooledDataSource(ClassLoader driverClassLoader, String driver, String url, Properties driverProperties) {
    this.driverClassLoader = driverClassLoader;
    this.driver = driver;
    this.url = url;
    this.driverProperties = driverProperties;
  }

  /**
   * 获取数据库连接
   * @return Connection
   */
  @Override
  public Connection getConnection() throws SQLException {
    return doGetConnection(username, password);
  }

  @Override
  public Connection getConnection(String username, String password) throws SQLException {
    return doGetConnection(username, password);
  }

  private Connection doGetConnection(String username, String password) throws SQLException {
    // 1、把用户名、密码以及driverProperties里的属性收集下
    Properties props = new Properties();
    if (driverProperties != null) {
      props.putAll(driverProperties);
    }
    if (username != null) {
      props.setProperty("user", username);
    }
    if (password != null) {
      props.setProperty("password", password);
    }
    // 2、调用doGetConnection(Properties properties)
    return doGetConnection(props);
  }

  /**
   * 可以看到每次都是调用DriverManager.getConnection()获取新的连接
   */
  private Connection doGetConnection(Properties properties) throws SQLException {
    // 1、加载驱动
    initializeDriver();
    // 2、获取数据库连接,除了用户名和密码,以"driver."开头的属性也被传递进去了
    Connection connection = DriverManager.getConnection(url, properties);
    // 3、配置连接是否自动提交、事务级别。(先获取连接，后配置连接）
    configureConnection(connection);
    // 4、返回
    return connection;
  }

  /**
   * 设置连接超时
   *
   * 一般不这么搞,一般都是使用这种方式设置连接超时
   *   jdbc:mysql://127.0.0.1:3066/test?connectTimeout=3000&socketTimeout=60000
   *
   *    1、connectionRequestTimout：指从连接池获取连接的timeout
   *    2、connectionTimeout：指客户端和服务器建立连接的timeout就是http请求的三个阶段，
   *                      一：建立连接；
   *                      二：数据传送；
   *                      三，断开连接。超时后会ConnectionTimeOutException
   *    3、socketTimeout：指客户端从服务器读取数据的timeout，超出后会抛出SocketTimeOutException
   * @param loginTimeout s
   */
  @Override
  public void setLoginTimeout(int loginTimeout) {
    DriverManager.setLoginTimeout(loginTimeout);
  }

  @Override
  public int getLoginTimeout() {
    return DriverManager.getLoginTimeout();
  }

  /**
   * 设置驱动管理器和所有驱动程序使用的记录/跟踪PrintWriter对象。 没哈用
   * @param logWriter  PrintWriter
   */
  @Override
  public void setLogWriter(PrintWriter logWriter) {
    DriverManager.setLogWriter(logWriter);
  }

  @Override
  public PrintWriter getLogWriter() {
    return DriverManager.getLogWriter();
  }

  public synchronized void setDriver(String driver) {
    this.driver = driver;
  }


  public Boolean isAutoCommit() {
    return autoCommit;
  }

  /**
   * 加载驱动并初始化,注意这个方法是加了同步锁的。
   */
  private synchronized void initializeDriver() throws SQLException {
	  // 1、已经加载就跳过
    if (!registeredDrivers.containsKey(driver)) {
      Class<?> driverType;
      try {
        if (driverClassLoader != null) {
          // 1.1.1、使用指定的类加载器加载类,设置为true时会类进行初始化，代表会执行类中的静态代码块，以及对静态变量的赋值等操作
          driverType = Class.forName(driver, true, driverClassLoader);
        } else {
          // 1.1.2、使用mybatis的资源处理类来加载类
          driverType = Resources.classForName(driver);
        }
        // 1.2、实例化
        Driver driverInstance = (Driver)driverType.newInstance();
        // 1.3、将驱动注册进DriverManager(类静态代码块里已经自动注册过了,这里又注册一次，目的？）
        DriverManager.registerDriver(new DriverProxy(driverInstance));
        // 1.4、将驱动信息和驱动注册进容器
        registeredDrivers.put(driver, driverInstance);
      } catch (Exception e) {
        throw new SQLException("Error setting driver on UnpooledDataSource. Cause: " + e);
      }
    }
  }

  private void configureConnection(Connection conn) throws SQLException {
    // 1、设置是否自动提交
    if (autoCommit != null && autoCommit != conn.getAutoCommit()) {
      conn.setAutoCommit(autoCommit);
    }
    // 2、设置事务隔离界别
    if (defaultTransactionIsolationLevel != null) {
      conn.setTransactionIsolation(defaultTransactionIsolationLevel);
    }
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

  /**
   * 这里使用的静态代理,其他都是调用的真实角色的方法,
   * 主要是getParentLogger(),真实角色的这个方法直接抛异常，所以代理类重新实现了下
   */
  private static class DriverProxy implements Driver {
    private Driver driver;

    DriverProxy(Driver d) {
      this.driver = d;
    }

    @Override
    public boolean acceptsURL(String u) throws SQLException {
      return this.driver.acceptsURL(u);
    }

    @Override
    public Connection connect(String u, Properties p) throws SQLException {
      return this.driver.connect(u, p);
    }

    @Override
    public int getMajorVersion() {
      return this.driver.getMajorVersion();
    }

    @Override
    public int getMinorVersion() {
      return this.driver.getMinorVersion();
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String u, Properties p) throws SQLException {
      return this.driver.getPropertyInfo(u, p);
    }

    @Override
    public boolean jdbcCompliant() {
      return this.driver.jdbcCompliant();
    }

    // @Override only valid jdk7+
    @Override
    public Logger getParentLogger() {
      return Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
    }
  }

}
