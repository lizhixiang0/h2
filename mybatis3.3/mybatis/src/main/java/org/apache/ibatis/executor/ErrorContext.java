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
package org.apache.ibatis.executor;

/**
 * ErrorContext 将异常信息构建成易于发现异常的格式
 * @author Clinton Begin
 * @blog "https://www.jianshu.com/p/901e37d05853
 */
public class ErrorContext {

  /**
   * 获得行分隔符,不同的操作系统不一样,所以不能写死、windows下换行符为\r\n,linux下换行符为\n
   */
  private static final String LINE_SEPARATOR = System.lineSeparator();
  /**
   * 使用ThreadLocal,每个线程都创建的是自己的ErrorContext副本
   * withInitial方法里面传递的参数是一个Supplier,只有LOCAL.get()时才会new出这个对象,当然如果存在就不会new.
   *
   * 补充说明：这个ThreadLocal看起来挺玄幻,其实就是为每一个线程维护了一个ThreadLocalMap
   * 优点：
   *    1、使用ThreadLocal的优点是无论程序运行到任何地方，只要还是当前线程,都可以拿到ErrorContext,避免多次传递
   *       用到mybatis上就是我们就能直接取到之前执行本SQL的线程上的各种信息, 也就很方便的构建出异常发生时的上下文，快速排错
   *
   *    2、线程间数据隔离
   *
   * 老版：private static final ThreadLocal<ErrorContext> LOCAL = new ThreadLocal<>();
   */

  private static final ThreadLocal<ErrorContext> LOCAL = ThreadLocal.withInitial(ErrorContext::new);
  /**
   * 当我们想把当前线程的ErrorContext存起来，就new一个新的ErrorContext,然后把旧的存到这个新的属性stored
   */
  private ErrorContext stored;
  private String resource;
  private String activity;
  private String object;
  private String message;
  private String sql;
  private Throwable cause;

  /**
   * 无参构造器私有化======》单例模式
   */
  private ErrorContext() {}

  /**
   * 老版：
          public static ErrorContext instance() {
            //试图拿到该线程自己的ErrorContext副本,没有则创建
            ErrorContext context = LOCAL.get();
            if (context == null) {
              context = new ErrorContext();
              LOCAL.set(context);
            }
            return context;
          }

    新版其实和老版本是一样的，但是写法就高级了一点！
   */
  public static ErrorContext instance() {
    return LOCAL.get();
  }

  /**
   * store()和recall()成对使用,
   * stored 变量充当一个中介,store()方法将当前 ErrorContext 保存下来，调用 recall() 方法再将该 ErrorContext 实例传递给 LOCAL
   * 可以防止信息污染。
   * 这对方法只在processBefore()方法前后被调用过,processBefore()方法执行先于主体数据库执行，如果不进行这个成组操作，之后的主体操作出现的异常信息可能被前者所污染，导致排错困难
   * @return
   */
  public ErrorContext store() {
    ErrorContext newContext = new ErrorContext();
    newContext.stored = this;
    LOCAL.set(newContext);
    return LOCAL.get();
  }

  /**
   * 应该是和store相对应的方法，store是存储起来，recall是召回
   * @return
   */
  public ErrorContext recall() {
    if (stored != null) {
      LOCAL.set(stored);
      stored = null;
    }
    return LOCAL.get();
  }

  /**
   * 每次调用这玩意儿必须手动调用一下reset方法,通产是在catch里使用ErrorContext,然后在finally里使用reset ！！！保证每次使用ErrorContext她都像个小姑娘一样干干净净
   * @return 重置变量
   * @note 为变量赋 null 值，以便 gc 的执行，必须手动清空ThreadLocalMap来防止内存泄漏
   *
   */
  public ErrorContext reset() {
    resource = null;
    activity = null;
    object = null;
    message = null;
    sql = null;
    cause = null;
    LOCAL.remove();
    return this;
  }

  /**
   *
   * @param resource 存储异常存在于哪个资源文件中
   * @return 建造者模式返回 this,链式调用。。。
   */
  public ErrorContext resource(String resource) {
    this.resource = resource;
    return this;
  }

  /**
   *
   * @param activity 存储异常是做什么操作时发生的
   * @return 建造者模式返回 this
   */
  public ErrorContext activity(String activity) {
    this.activity = activity;
    return this;
  }

  /**
   *
   * @param object 存储哪个对象操作时发生异常。
   * @return 建造者模式返回 this
   */
  public ErrorContext object(String object) {
    this.object = object;
    return this;
  }

  /**
   *
   * @param message 存储异常的概览信息。
   * @return 建造者模式返回 this
   */
  public ErrorContext message(String message) {
    this.message = message;
    return this;
  }

  /**
   *
   * @param sql  存储发生日常的 SQL 语句。
   * @return 建造者模式返回 this
   */
  public ErrorContext sql(String sql) {
    this.sql = sql;
    return this;
  }

  /**
   *
   * @param cause 存储详细的 Java 异常日志
   * @return 建造者模式返回 this
   */
  public ErrorContext cause(Throwable cause) {
    this.cause = cause;
    return this;
  }



  /**
   * @return 打印报错信息
   */
  @Override
  public String toString() {
    StringBuilder description = new StringBuilder();

    // 存储异常的概览信息
    if (this.message != null) {
      description.append(LINE_SEPARATOR);
      description.append("### ");
      description.append(this.message);
    }

    // 存储异常存在于哪个资源文件中
    if (resource != null) {
      description.append(LINE_SEPARATOR);
      description.append("### The error may exist in ");
      description.append(resource);
    }

    // 存储哪个对象操作时发生异常
    if (object != null) {
      description.append(LINE_SEPARATOR);
      description.append("### The error may involve ");
      description.append(object);
    }

    // 存储异常是做什么操作时发生的
    if (activity != null) {
      description.append(LINE_SEPARATOR);
      description.append("### The error occurred while ");
      description.append(activity);
    }

    // 存储发生日常的 SQL 语句。
    if (sql != null) {
      description.append(LINE_SEPARATOR);
      description.append("### SQL: ");
      //把sql压缩到一行里
      description.append(sql.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim());
    }

    // 存储详细的 Java 异常日志
    if (cause != null) {
      description.append(LINE_SEPARATOR);
      description.append("### Cause: ");
      description.append(cause.toString());
    }
    return description.toString();
  }

  /**
   * 实例：
   * ### Error updating database.  Cause: java.sql.SQLException: Incorrect integer value: 'ss' for column 'phone' at row 1
   * ### The error may involve com.mybatis.lizx.dao.PersonDao.insert-Inline
   * ### The error occurred while setting parameters
   * ### SQL: INSERT INTO person (name, age, phone, email, address)         VALUES(?,?,?,?,?)
   * ### Cause: java.sql.SQLException: Incorrect integer value: 'ss' for column 'phone' at row 1
   */

}
