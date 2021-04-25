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
package org.apache.ibatis.mapping;

import java.util.Collections;
import java.util.Map;

import org.apache.ibatis.session.Configuration;

/**
 * 鉴别器
 * 有时一个查询也许返回很多不同数据类型的结果集。鉴别器的表现很像 Java 语言中的 switch 语句。
 * <discriminator javaType="int" column="draft" jdbcType="" typeHandler="">
 *    <case value="1" resultMap="DraftPost"/>
 * </discriminator>
 * @author Clinton Begin
 */
public class Discriminator {
  /**
   *  Discriminator结果自身的结果映射
   */
  private ResultMapping resultMapping;

  /**
   * <name,resultMap>容器
   */
  private Map<String, String> discriminatorMap;

  private Discriminator() {
  }

  public static class Builder {
    private Discriminator discriminator = new Discriminator();

    public Builder(Configuration configuration, ResultMapping resultMapping, Map<String, String> discriminatorMap) {
      discriminator.resultMapping = resultMapping;
      discriminator.discriminatorMap = discriminatorMap;
    }

    /**
     * 啥也没干，就是验证了下
     */
    public Discriminator build() {
      // 验证resultMapping不为null
      assert discriminator.resultMapping != null;
      // 验证discriminatorMap不为null
      assert discriminator.discriminatorMap != null;
      // 验证discriminatorMap不为空
      assert !discriminator.discriminatorMap.isEmpty();
      // 将discriminatorMap锁定为不可变集合
      discriminator.discriminatorMap = Collections.unmodifiableMap(discriminator.discriminatorMap);
      // 返回discriminator
      return discriminator;
    }
  }

  public ResultMapping getResultMapping() {
    return resultMapping;
  }

  public Map<String, String> getDiscriminatorMap() {
    return discriminatorMap;
  }

  public String getMapIdFor(String s) {
    return discriminatorMap.get(s);
  }

}
