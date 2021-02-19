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
 * 包装器工厂接口,定义了包装器工厂的行为
 * @author Clinton Begin
 */
public interface ObjectWrapperFactory {
    /**
     * 1、判断有没有对象包装器
     * @param object obj
     * @return boolean
     */
  boolean hasWrapperFor(Object object);

    /**
     * 2、用来获得包装器
     * @param metaObject obj
     * @param object obj
     * @return boolean
     */
  ObjectWrapper getWrapperFor(MetaObject metaObject, Object object);

}
