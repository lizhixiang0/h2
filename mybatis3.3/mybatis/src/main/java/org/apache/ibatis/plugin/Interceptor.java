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
package org.apache.ibatis.plugin;

import java.util.Properties;

/**
 * 拦截器
 * 实例：
 *    .@Intercepts({
 *            .@Signature(type = StatementHandler.class, method = "prepare", args = {Connection.class}),
 *            .@Signature(type = ResultSetHandler.class, method = "handleResultSets", args = {Statement.class})
 *    })
 *    public class TestInterceptor implements Interceptor {

 *      /**
 *        * 只对两种类型的进行处理
 *        * <br>StatementHandler
 *        * <br>ResultSetHandler
 *        *
 *      public Object intercept(Invocation invocation) throws Throwable {
 *
 *        if (invocation.getTarget() instanceof StatementHandler) {
 *            return result;
 *        }else if (invocation.getTarget() instanceof ResultSetHandler) {
 *            return result;
 *         }
 *        return null;
 *     }
 *
 *      /**
 *      * 只拦截这两种类型的
 *      * <br>StatementHandler
 *      * <br>ResultSetHandler
 *      *
 *      public Object plugin(Object target) {
 *        if (target instanceof StatementHandler || target instanceof ResultSetHandler) {
 *             return Plugin.wrap(target, this);
 *         } else {
 *             return target;
 *         }
 *      }
 *
 *      public void setProperties(Properties properties) {}
 *
 *   }
 *
 * @author Clinton Begin
 * @link "https://www.jianshu.com/p/7c7b8c2c985d
 */
public interface Interceptor {

  /**
   * intercept方法就是拦截后要执行的方法
   * @param invocation 方法执行器
   * @return 执行结果
   */
  Object intercept(Invocation invocation) throws Throwable;

  /**
   * plugin方法是插件用于包装目标对象的，如果是需要拦截的对对象，那就返回其代理类
   * 如果不是需要拦截的对象，那就直接返回目标对象
   * 官方推荐使用 ：
   *       if (target instanceof xxx) {
   *               return Plugin.wrap(target, this);
   *       } else {
   *               return target;
   *  *    }
   * @param target 被拦截的对象
   * @return 被拦截的对象或者该对象的代理
   */
  Object plugin(Object target);

  /**
   * Mybatis进行配置插件的时候可以配置相关的自定义属性，这个看怎么定义插件的
   * @param properties p
   */
  void setProperties(Properties properties);

}
