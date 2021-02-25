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
package org.apache.ibatis.reflection;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import lombok.Data;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.reflection.property.PropertyTokenizer;
import org.apache.ibatis.reflection.wrapper.BeanWrapper;
import org.apache.ibatis.reflection.wrapper.CollectionWrapper;
import org.apache.ibatis.reflection.wrapper.MapWrapper;
import org.apache.ibatis.reflection.wrapper.ObjectWrapper;
import org.apache.ibatis.reflection.wrapper.ObjectWrapperFactory;

/**
 *  MetaObject ,主要是调用包装器中的方法
 *  支持对普通JavaBean、Collection类、Map类三种类型对象的操作
 *  可以参考MetaObjectTest来跟踪调试，基本上用到了reflection包下所有的类
 * @author Clinton Begin
 */
@Data
public class MetaObject {

  /**
   * 1、原始JavaBean对象
   */
  private Object originalObject;
  /**
   * 2、负责实例化原始JavaBean对象的工厂对象
   */
  private ObjectFactory objectFactory;
  /**
   * 3、封装了originalObject对象的包装对象,根据JavaBean的类型，可能为 BeanWrapper、MapWrapper、CollectionWrapper。
   */
  private ObjectWrapper objectWrapper;
  /**
   * 4、负责创建ObjectWrapper的工厂对象
   */
  private ObjectWrapperFactory objectWrapperFactory;

  /**
   * 构造私有化
   */
  private MetaObject(Object object, ObjectFactory objectFactory, ObjectWrapperFactory objectWrapperFactory) {
    this.originalObject = object;
    this.objectFactory = objectFactory;
    this.objectWrapperFactory = objectWrapperFactory;

    if (object instanceof ObjectWrapper) {
        //如果对象本身已经是ObjectWrapper型，则直接赋给objectWrapper
      this.objectWrapper = (ObjectWrapper) object;
    } else if (objectWrapperFactory.hasWrapperFor(object)) {
      //若objectWrapperFactory能够为该原始对象创建对应的ObjectWrapper对象，则优先使用objectWrapperFactory
      // 但DefaultObjectWrapperFactory.hasWrapperFor()始终返回false，用户可以自定义ObjectWrapperFactory实现进行扩展。
      this.objectWrapper = objectWrapperFactory.getWrapperFor(this, object);
    } else if (object instanceof Map) {
        //如果是Map型，返回MapWrapper
      this.objectWrapper = new MapWrapper(this, (Map) object);
    } else if (object instanceof Collection) {
        //如果是Collection型，返回CollectionWrapper
      this.objectWrapper = new CollectionWrapper(this, (Collection) object);
    } else {
        //除此以外，返回BeanWrapper
      this.objectWrapper = new BeanWrapper(this, object);
    }
  }

  /**
   * MetaObject 的构造器是私有的,只能通过静态方法forObject()创建对象实例
   * @param object obj
   * @param objectFactory objectFactory
   * @param objectWrapperFactory objectWrapperFactory
   * @return MetaObject
   */
  public static MetaObject forObject(Object object, ObjectFactory objectFactory, ObjectWrapperFactory objectWrapperFactory) {
    // 若Object为空，则统一返回 SystemMetaObject.NULL_META_OBJECT
    // 反过来，若判断到一个 JavaBean 对象对应的 MetaObject 为 SystemMetaObject.NULL_META_OBJECT，可以判断对象为空
    if (object == null) {
      return SystemMetaObject.NULL_META_OBJECT;
    } else {
      return new MetaObject(object, objectFactory, objectWrapperFactory);
    }
  }

  //--------以下方法都是委派给包装器ObjectWrapper------

  //查找属性
  public String findProperty(String propName, boolean useCamelCaseMapping) {
    return objectWrapper.findProperty(propName, useCamelCaseMapping);
  }

  //取得getter的名字列表
  public String[] getGetterNames() {
    return objectWrapper.getGetterNames();
  }

  //取得setter的名字列表
  public String[] getSetterNames() {
    return objectWrapper.getSetterNames();
  }

  //取得setter的类型列表
  public Class<?> getSetterType(String name) {
    return objectWrapper.getSetterType(name);
  }

  //取得getter的类型列表
  public Class<?> getGetterType(String name) {
    return objectWrapper.getGetterType(name);
  }

  //是否有指定的setter
  public boolean hasSetter(String name) {
    return objectWrapper.hasSetter(name);
  }

  //是否有指定的getter
  public boolean hasGetter(String name) {
    return objectWrapper.hasGetter(name);
  }


  public MetaObject metaObjectForProperty(String name) {
    //获得属性名对应的对象
    Object value = getValue(name);
    //为该属性生成元对象
    return MetaObject.forObject(value, objectFactory, objectWrapperFactory);
  }

  //根据属性名获得属性对象
  public Object getValue(String name) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    if (prop.hasNext()) {
      MetaObject metaValue = metaObjectForProperty(prop.getIndexedName());
      if (metaValue == SystemMetaObject.NULL_META_OBJECT) {
        return null;
      } else {
          //否则继续看下一层，递归调用getValue
       return metaValue.getValue(prop.getChildren());
      }
    } else {
      return objectWrapper.get(prop);
    }
  }

  //设置值
  public void setValue(String name, Object value) {
    PropertyTokenizer prop = new PropertyTokenizer(name);
    if (prop.hasNext()) {
      MetaObject metaValue = metaObjectForProperty(prop.getIndexedName());
      if (metaValue == SystemMetaObject.NULL_META_OBJECT) {
        if (value == null && prop.getChildren() != null) {
          return;
        } else {
          metaValue = objectWrapper.instantiatePropertyValue(name, prop, objectFactory);
        }
      }
      //递归调用setValue
      metaValue.setValue(prop.getChildren(), value);
    } else {
      objectWrapper.set(prop, value);
    }
  }

  //是否是集合
  public boolean isCollection() {
    return objectWrapper.isCollection();
  }

  //添加属性
  public void add(Object element) {
    objectWrapper.add(element);
  }

  //添加属性
  public <E> void addAll(List<E> list) {
    objectWrapper.addAll(list);
  }

}
