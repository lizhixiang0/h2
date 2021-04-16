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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.ibatis.session.Configuration;

/**
 * @author Clinton Begin
 *
 *    * 1、使用trim标签代替where的功能
 *    * <select id="findActiveBlogLike" resultType="Blog">
 *    *    select * from user
 *    *　　<trim prefix="WHERE" prefixOverrides="AND |OR">
 *    *　　　　<if test="name != null and name.length()>0">
 *    *         AND name=#{name}
 *    *       </if>
 *    *　　　　<if test="gender != null and gender.length()>0">
 *    *         AND gender=#{gender}
 *    *       </if>
 *    *　　</trim>
 *    * </select>
 *    * 注：假如说name和gender的值都不为null的话打印的SQL为：select * from user where name = 'xx' and gender = 'xx'，是不存在第一个and的
 *    *    那么上面两个属性的意思是：
 *    *                  prefix：WHERE前缀
 *    *                  prefixOverrides：裁剪掉第一个and或者是or
 *    *
 *    *
 *    * 2、使用trim标签代替set的功能
 *    * <update>
 *    *    update user
 *    * 　　<trim prefix="set" suffixOverrides="," suffix=" where id = #{id} ">
 *    *        <if test="name != null and name.length()>0">
 *    *          name=#{name} ,
 *    *        </if>
 *    * 　　　　<if test="gender != null and gender.length()>0">
 *    *          gender=#{gender} ,
 *    *        </if>
 *    * 　　</trim>
 *    * </update>
 *    * 注：假如说name和gender的值都不为null的话打印的SQL为：update user set name='xx' , gender='xx' where id='x'
 *    *    那么上面三个属性的意思是：
 *    *                          prefix：set前缀
 *    *                          suffix：后缀
 *    *                          suffixOverrides：裁剪掉最后一个逗号（也可以是其他的标记，就像是上面前缀中的and一样）
 */
public class TrimSqlNode implements SqlNode {
  /**
   * trim下的所有if文本
   */
  private SqlNode contents;
  /**
   * 前缀,必定义的,通常会是 where 、set 、(
   */
  private String prefix;
  /**
   * 后缀,不一定非要定义,通常会是 )、where id = #{id}
   */
  private String suffix;
  /**
   * 被覆盖的最前缀,通常会写"and | or"
   */
  private List<String> prefixesToOverride;
  /**
   * 被覆盖的最后缀,通常会写","
   */
  private List<String> suffixesToOverride;
  private Configuration configuration;

  public TrimSqlNode(Configuration configuration, SqlNode contents, String prefix, String prefixesToOverride, String suffix, String suffixesToOverride) {
    this(configuration, contents, prefix, parseOverrides(prefixesToOverride), suffix, parseOverrides(suffixesToOverride));
  }

  protected TrimSqlNode(Configuration configuration, SqlNode contents, String prefix, List<String> prefixesToOverride, String suffix, List<String> suffixesToOverride) {
    this.contents = contents;
    this.prefix = prefix;
    this.prefixesToOverride = prefixesToOverride;
    this.suffix = suffix;
    this.suffixesToOverride = suffixesToOverride;
    this.configuration = configuration;
  }

  @Override
  public boolean apply(DynamicContext context) {
    FilteredDynamicContext filteredDynamicContext = new FilteredDynamicContext(context);
    boolean result = contents.apply(filteredDynamicContext);
    filteredDynamicContext.applyAll();
    return result;
  }

  private static List<String> parseOverrides(String overrides) {
    if (overrides != null) {
      final StringTokenizer parser = new StringTokenizer(overrides, "|", false);
      final List<String> list = new ArrayList<>(parser.countTokens());
      while (parser.hasMoreTokens()) {
        list.add(parser.nextToken().toUpperCase(Locale.ENGLISH));
      }
      return list;
    }
    return Collections.emptyList();
  }

  private class FilteredDynamicContext extends DynamicContext {
    private DynamicContext delegate;
    private boolean prefixApplied;
    private boolean suffixApplied;
    private StringBuilder sqlBuffer;

    public FilteredDynamicContext(DynamicContext delegate) {
      super(configuration, null);
      this.delegate = delegate;
      this.prefixApplied = false;
      this.suffixApplied = false;
      this.sqlBuffer = new StringBuilder();
    }

    public void applyAll() {
      sqlBuffer = new StringBuilder(sqlBuffer.toString().trim());
      String trimmedUppercaseSql = sqlBuffer.toString().toUpperCase(Locale.ENGLISH);
      if (trimmedUppercaseSql.length() > 0) {
        applyPrefix(sqlBuffer, trimmedUppercaseSql);
        applySuffix(sqlBuffer, trimmedUppercaseSql);
      }
      delegate.appendSql(sqlBuffer.toString());
    }

    @Override
    public Map<String, Object> getBindings() {
      return delegate.getBindings();
    }

    @Override
    public void bind(String name, Object value) {
      delegate.bind(name, value);
    }

    @Override
    public int getUniqueNumber() {
      return delegate.getUniqueNumber();
    }

    @Override
    public void appendSql(String sql) {
      sqlBuffer.append(sql);
    }

    @Override
    public String getSql() {
      return delegate.getSql();
    }

    private void applyPrefix(StringBuilder sql, String trimmedUppercaseSql) {
      if (!prefixApplied) {
        prefixApplied = true;
        if (prefixesToOverride != null) {
          for (String toRemove : prefixesToOverride) {
            if (trimmedUppercaseSql.startsWith(toRemove)) {
              sql.delete(0, toRemove.trim().length());
              break;
            }
          }
        }
        if (prefix != null) {
          sql.insert(0, " ");
          sql.insert(0, prefix);
        }
      }
    }

    private void applySuffix(StringBuilder sql, String trimmedUppercaseSql) {
      if (!suffixApplied) {
        suffixApplied = true;
        if (suffixesToOverride != null) {
          for (String toRemove : suffixesToOverride) {
            if (trimmedUppercaseSql.endsWith(toRemove) || trimmedUppercaseSql.endsWith(toRemove.trim())) {
              int start = sql.length() - toRemove.trim().length();
              int end = sql.length();
              sql.delete(start, end);
              break;
            }
          }
        }
        if (suffix != null) {
          sql.append(" ");
          sql.append(suffix);
        }
      }
    }

  }

}
