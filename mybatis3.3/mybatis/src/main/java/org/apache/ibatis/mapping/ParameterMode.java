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

/**
 * 参数模式
 *
 * @author Clinton Begin
 * @link "https://blog.csdn.net/nfzhlk/article/details/83416413
 * @link 存储过程中in，out，inout的区别： "https://blog.csdn.net/zy103118/article/details/90697345
 */
public enum ParameterMode {
  /**
   * 输入参数（外界传入的参数）
   */
  IN,
  /**
   * 输出参数（输出到外界的参数）
   */
  OUT,
  /**
   * 输入输出参数（既能作为输入参数又能作为输出参数）
   */
  INOUT
}
