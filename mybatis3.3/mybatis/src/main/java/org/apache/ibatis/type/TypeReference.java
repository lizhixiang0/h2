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
package org.apache.ibatis.type;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/**
 * 用来通过使用泛型参数与反射原理，从某个TypeHandler中获取对应的原生java类型保存在rawType字段中
 * 这个类型引用的目的就是为了持有这个具体的类型处理器所处理的Java类型的原生类型。
 * @author admin
 */
public abstract class TypeReference<T> {

  /**
   * 保存某TypeHandler对应的原生java类型
   */
  private final Type rawType;

  /**
   * 无参构造，protected级别，在子类的构造方法里调用
   */
  protected TypeReference() {
    rawType = getSuperclassTypeParameter(this.getClass());
  }

  Type getSuperclassTypeParameter(Class<?> clazz) {
    // 1、得到泛型T的实际类型，通过给定参数clazz的getGenericSuperclass()方法来获取该类的泛型父类，如果要获取不带泛型的父类可使用getSuperclass()方法
    Type genericSuperclass = clazz.getGenericSuperclass();
    // 2、如果父类是Class类的实例，则不是泛型类，继续往上递归 ,这里不是很懂。
    if (genericSuperclass instanceof Class) {
      if (TypeReference.class != genericSuperclass) {
        return getSuperclassTypeParameter(clazz.getSuperclass());
      }
      throw new TypeException("'" + getClass() + "' extends TypeReference but misses the type parameter. "
        + "Remove the extension or add a type parameter to it.");
    }
    // 当父类的类型是ParameterizedType（泛型类）时，通过getActualTypeArguments获取泛型的类型
    Type rawType = ((ParameterizedType) genericSuperclass).getActualTypeArguments()[0];
    // 如果该类型还是参数化类型（仍然带有泛型，即泛型嵌套的模式），那么就需要再次执行getActualTypeArguments()方法来获取其泛型类型（参数类型），最后将该类型返回（赋值给字段）
    if (rawType instanceof ParameterizedType) {
      rawType = ((ParameterizedType) rawType).getRawType();
    }
    return rawType;
  }

  /**
   *  getRawType()方法重点被调用的地方在TypeHandlerRegistry（类型处理器注册器）中，在没有指定JavaType而只有TypeHandler的情况下，
   *  调用该TypeHandler的getRawType()方法来获取其原生类型（即参数类型）来作为其JavaType来进行类型处理器的注册
   */
  public final Type getRawType() {
    return rawType;
  }

  /**
   * 我们可以看到在该类中有两个public方法getRawType()和toString()方法，意味着这个原生类型是为了被外部调用而设
   */
  @Override
  public String toString() {
    return rawType.toString();
  }

}
