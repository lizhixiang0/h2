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
package org.apache.ibatis.reflection.wrapper;

import org.apache.ibatis.reflection.MetaObject;

/**
 * 对象包装器工厂,定义了两个方法
 * @author Clinton Begin
 */
public interface ObjectWrapperFactory {
    /**
     * 1、有没有包装器提供给当前对象
     * @param object obj
     * @return boolean
     */
  boolean hasWrapperFor(Object object);

    /**
     * 2、得到包装器用来包装当前对象
     * @param metaObject obj
     * @param object obj
     * @return boolean
     */
  ObjectWrapper getWrapperFor(MetaObject metaObject, Object object);

}
