/*
 *    Copyright 2009-2011 the original author or authors.
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
package org.apache.ibatis.builder;

import java.util.List;

import org.apache.ibatis.mapping.Discriminator;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.mapping.ResultMapping;

/**
 * 结果映射解析器,包装了一下MapperBuilderAssistant的addResultMap方法
 * @author Eduardo Macarron
 */
public class ResultMapResolver {
  /**
   * 当前xml映射文件对应的构建助手
   */
  private final MapperBuilderAssistant assistant;
  /**
   * 当前ResultMap的唯一标识
   */
  private String id;
  /**
   * 当前ResultMap对应的java类型
   */
  private Class<?> type;
  /**
   * 当前ResultMap继承的ResultMap
   */
  private String extend;
  /**
   * 当前ResultMap的辨别器
   */
  private Discriminator discriminator;
  /**
   * 当前ResultMap下的所有结果映射
   */
  private List<ResultMapping> resultMappings;
  /**
   * 是否自动映射
   */
  private Boolean autoMapping;

  public ResultMapResolver(MapperBuilderAssistant assistant, String id, Class<?> type, String extend, Discriminator discriminator, List<ResultMapping> resultMappings, Boolean autoMapping) {
    this.assistant = assistant;
    this.id = id;
    this.type = type;
    this.extend = extend;
    this.discriminator = discriminator;
    this.resultMappings = resultMappings;
    this.autoMapping = autoMapping;
  }

  /**
   * 解析,生成ResultMap
   * @return ResultMap
   */
  public ResultMap resolve() {
    // 调用MapperBuilderAssistant.addResultMap
    return assistant.addResultMap(this.id, this.type, this.extend, this.discriminator, this.resultMappings, this.autoMapping);
  }

}