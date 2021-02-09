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

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ReflectPermission;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Wrapper;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import lombok.Data;
import org.apache.ibatis.mapping.ResultMap;
import org.apache.ibatis.reflection.invoker.GetFieldInvoker;
import org.apache.ibatis.reflection.invoker.Invoker;
import org.apache.ibatis.reflection.invoker.MethodInvoker;
import org.apache.ibatis.reflection.invoker.SetFieldInvoker;
import org.apache.ibatis.reflection.property.PropertyNamer;

/**
 *   Reflector是Mybatis中反射模块的基础，每个Reflector对象都对应着一个类。
 * @blog "https://blog.csdn.net/hou_ge/article/details/100666259
 * @author Clinton Begin
 */
@Data
public class Reflector {

  private static boolean classCacheEnabled = true;

  private static final String[] EMPTY_STRING_ARRAY = new String[0];

  //这里使用了一个Map来做缓存，注意使用的是ConcurrentHashMap,保证线程安全
  private static final Map<Class<?>, Reflector> REFLECTOR_MAP = new ConcurrentHashMap<>();

  private Class<?> type;

  //默认构造函数
  private Constructor<?> defaultConstructor;
  //可读属性的名称集合，可读属性就是存在相应getter方法的属性，初始值为空数纽   getName ---> name
  private String[] readablePropertyNames;
  //可写属性的名称集合，可写属性就是存在相应setter方法的属性，初始值为空数纽
  private String[] writeablePropertyNames;
  //属性相应的setter方法，key是属性名称,value是MethodInvoker对象（mybatis实现的Invoker类,MethodInvoker(?,?)相当于调用set方法）
  private Map<String, Invoker> setMethods = new HashMap<>();
  //属性相应的getter方法集合， key是属性名称， value是MethodInvoker对象（mybatis实现的Invoker类,MethodInvoker(?,?)相当于调用get方法）
  private Map<String, Invoker> getMethods = new HashMap<>();
  //属性相应的setter方法的参数值类型， key是属性名称， value是setter方法的参数类型
  private Map<String, Class<?>> setTypes = new HashMap<>();
  //属性相应的getter方法的返回位类型， key是属性名称， value是getter方法的返回值类型
  private Map<String, Class<?>> getTypes = new HashMap<>();
  //所有属性名称的集合
  private Map<String, String> caseInsensitivePropertyMap = new HashMap<>();

  /*
   * Gets an instance of ClassInfo for the specified class.
   * 得到某个类的反射器，是静态方法，而且要缓存，又要多线程，所以REFLECTOR_MAP是一个ConcurrentHashMap
   * @param clazz The class for which to lookup the method cache.
   * @return The method cache for the class
   */
  public static Reflector forClass(Class<?> clazz) {
    if (classCacheEnabled) {
      // synchronized (clazz) removed see issue #461
      //对于每个类来说，我们假设它是不会变的，这样可以考虑将这个类的信息(构造函数，getter,setter,字段)加入缓存，以提高速度
      Reflector cached = REFLECTOR_MAP.get(clazz);
      if (cached == null) {
        cached = new Reflector(clazz);
        REFLECTOR_MAP.put(clazz, cached);
      }
      return cached;
    } else {
      return new Reflector(clazz);
    }
  }

  /**
   * 在私有构造函数中，主要是对类的元信息进行解析，同时初始化相关字段数据。下面分别分析数据初始化的过程。其中，type字段就是class
   * @param clazz 类
   */
  private Reflector(Class<?> clazz) {
    type = clazz;
    //查找clazz的默认构造方法（无参构造方法）
    addDefaultConstructor(clazz);
    //处理clazz中的getter && is方法，填充getMethods集合和getTypes集合,注意这个顺序，先搞get后搞的set
    addGetMethods(clazz);
    //处理clazz中的setter方法，填充setMethods集合和setTypes集合
    addSetMethods(clazz);
    //处理没有getter/setter方法的字段,最后也是填充到setMethods和getMethods里去
    addFields(clazz);
    //根据getMethods/setMethods集合，初始化可读/写属性的名称集合
    readablePropertyNames = getMethods.keySet().toArray(new String[0]);
    writeablePropertyNames = setMethods.keySet().toArray(new String[0]);
    //初始化caseInsensitivePropertyMap集合，其中记录了所有大写格式的属性名称
    for (String propName : readablePropertyNames) {
      caseInsensitivePropertyMap.put(propName.toUpperCase(Locale.ENGLISH), propName);
    }
    for (String propName : writeablePropertyNames) {
      caseInsensitivePropertyMap.put(propName.toUpperCase(Locale.ENGLISH), propName);
    }
  }


  private void addDefaultConstructor(Class<?> clazz) {
    Constructor<?>[] consts = clazz.getDeclaredConstructors();
    //循环，找到没有入参的构造函数
    for (Constructor<?> constructor : consts) {
      if (constructor.getParameterTypes().length == 0) {
        if (canAccessPrivateMethods()) {
          try {
            // 关闭权限校验
            constructor.setAccessible(true);
          } catch (Exception ignored) {}
        }
        // isAccessible() 判断是否关闭权限校验
        if (constructor.isAccessible()) {
          this.defaultConstructor = constructor;
        }
      }
    }
  }

  private void addGetMethods(Class<?> cls) {
    Map<String, List<Method>> conflictingGetters = new HashMap<>(16);
    //得到所有方法，包括private方法，包括父类方法.包括接口方法,所以如果接口或者父类有 都有getName(String name),那name对应的get方法就会有两个或以上
    Method[] methods = getClassMethods(cls);
    for (Method method : methods) {
      String name = method.getName();
      if (name.startsWith("get") && name.length() > 3) {
        //没有参数的get方法才是我们需要的，这是一层筛选
        if (method.getParameterTypes().length == 0) {
          // getName ---> name
          name = PropertyNamer.methodToProperty(name);
          // 用computeIfAbsent来去重
          addMethodConflict(conflictingGetters, name, method);
        }
      } else if (name.startsWith("is") && name.length() > 2) {
        if (method.getParameterTypes().length == 0) {
          // isName ---> name
          name = PropertyNamer.methodToProperty(name);
          addMethodConflict(conflictingGetters, name, method);
        }
      }
    }
    // 收集到所有get()方法信息后开始处理
    resolveGetterConflicts(conflictingGetters);
  }

  private void addMethodConflict(Map<String, List<Method>> conflictingMethods, String name, Method method) {
    //这个 List<Method> 是 Map<String, List<Method>> 其中key对应的list ,所以看起来是重新创建了一个list ,其实不是
    // 这么写比较好理解：conflictingMethods.computeIfAbsent(name, k -> new ArrayList<>()).add(method);
    //就是判断Map有没有这个<k,v> ,没有就创建 ,有就直接操作这个k对应的v
    List<Method> list = conflictingMethods.computeIfAbsent(name, k -> new ArrayList<>());
    list.add(method);
  }

  private void resolveGetterConflicts(Map<String, List<Method>> conflictingGetters) {
    // 循环遍历Map集合，如果Value里只有一个元素（method），那就直接调用addGetMethod(name,method)方法
    // 如果对应的Method集合里有多个元素，则需要判断方法的返回值类型，（会把父类或者接口的也拿过来，此时需要筛选出当前类属性真正匹配的get方法）
    // 没有入参，所以不需要判断入参的类型
    for (String propName : conflictingGetters.keySet()) {
      List<Method> getters = conflictingGetters.get(propName);
      Iterator<Method> iterator = getters.iterator();
      Method firstMethod = iterator.next();
      if (getters.size() == 1) {
        addGetMethod(propName, firstMethod);
      } else {
        Method getter = firstMethod;
        Class<?> getterType = firstMethod.getReturnType();
        while (iterator.hasNext()) {
          Method method = iterator.next();
          Class<?> methodType = method.getReturnType();
          // 如果两个方法的返回值类型一样则直接抛出异常
          if (methodType.equals(getterType)) {throw new ReflectionException("Illegal overloaded getter method with ambiguous type for property " + propName + " in class " + firstMethod.getDeclaringClass() + ".  This breaks the JavaBeans " + "specification and can cause unpredicatble results."); }
          // 如果getterType是methodType的子类,那就不处理
          else if (methodType.isAssignableFrom(getterType)) {}
          // 如果getterType是methodType的父类,那就把子类拿出来
          else if (getterType.isAssignableFrom(methodType)) {
            getter = method;
            getterType = methodType;
          }
          // 其他情况直接报错
          else {throw new ReflectionException("Illegal overloaded getter method with ambiguous type for property " + propName + " in class " + firstMethod.getDeclaringClass() + ".  This breaks the JavaBeans " + "specification and can cause unpredicatble results."); }
        }
        addGetMethod(propName, getter);
      }
    }
  }

  private void addGetMethod(String name, Method method) {
    if (isValidPropertyName(name)) {
      getMethods.put(name, new MethodInvoker(method));
      getTypes.put(name, method.getReturnType());
    }
  }

  private void addSetMethods(Class<?> cls) {
    Map<String, List<Method>> conflictingSetters = new HashMap<>();
    //得到所有方法，包括private方法，包括父类方法.包括接口方法,所以如果接口或者父类有 都有setName(String name),那name对应的set方法就会有两个或以上
    Method[] methods = getClassMethods(cls);
    for (Method method : methods) {
      String name = method.getName();
      if (name.startsWith("set") && name.length() > 3) {
        // 只有getParameterTypes().length == 1 的方法才会被塞到conflictingGetters里去。
        if (method.getParameterTypes().length == 1) {
          name = PropertyNamer.methodToProperty(name);
          addMethodConflict(conflictingSetters, name, method);
        }
      }
    }
    resolveSetterConflicts(conflictingSetters);
  }

  private void resolveSetterConflicts(Map<String, List<Method>> conflictingSetters) {
    for (String propName : conflictingSetters.keySet()) {
      List<Method> setters = conflictingSetters.get(propName);
      Method firstMethod = setters.get(0);
      // 如果只有一个，直接处理就行，如果超过一个，那说明把父类或者接口中的也拿过来了，这些需要进行筛选，把与当前类get方法匹配的筛出来
      if (setters.size() == 1) {
        addSetMethod(propName, firstMethod);
      } else {
        //查看name对应的get方法，如果没有就抛出异常   （这个reflector要求当setName方法不止一个时，目标类必须有一个getName方法）
        Class<?> expectedType = getTypes.get(propName);
        if (expectedType == null) {
          throw new ReflectionException("Illegal overloaded setter method with ambiguous type for property " + propName + " in class " + firstMethod.getDeclaringClass() + ".  This breaks the JavaBeans " + "specification and can cause unpredicatble results.");
        } else {
          Iterator<Method> methods = setters.iterator();
          Method setter = null;
          while (methods.hasNext()) {
            Method method = methods.next();
            //找出与当前属性get方法匹配的set  ,匹配规则就是入参个数和返回参数的类型
            if (method.getParameterTypes().length == 1 && expectedType.equals(method.getParameterTypes()[0])) {
              setter = method;
              break;
            }
          }
          if (setter == null) {
            throw new ReflectionException("Illegal overloaded setter method with ambiguous type for property " + propName + " in class " + firstMethod.getDeclaringClass() + ".  This breaks the JavaBeans " + "specification and can cause unpredicatble results.");
          }
          addSetMethod(propName, setter);
        }
      }
    }
  }

  private void addSetMethod(String name, Method method) {
    if (isValidPropertyName(name)) {
      setMethods.put(name, new MethodInvoker(method));
      setTypes.put(name, method.getParameterTypes()[0]);
    }
  }

  private void addFields(Class<?> clazz) {
    Field[] fields = clazz.getDeclaredFields();
    for (Field field : fields) {
      if (canAccessPrivateMethods()) {
        try {
          field.setAccessible(true);
        } catch (Exception ignored) {}
      }
      if (field.isAccessible()) {
        // 处理没有set方法的属性
        if (!setMethods.containsKey(field.getName())) {
          // 返回属性的修饰符。  例如 public static   @blog "https://www.yiibai.com/javareflect/javareflect_field_getmodifiers.html
          int modifiers = field.getModifiers();
          // 不能是finale和static修饰的
          if (!(Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers))) {
            addSetField(field);
          }
        }
        // 处理没有get方法的属性
        if (!getMethods.containsKey(field.getName())) {
          addGetField(field);
        }
      }
    }
    if (clazz.getSuperclass() != null) {
      // 父类也不放过，递归处理，爷爷也不放过
      addFields(clazz.getSuperclass());
    }
  }

  // 我以为木有set方法的属性就不管了，没想到木有set的属性待遇更高，直接给他构造Invoker，黄袍加身！！
  private void addSetField(Field field) {
    if (isValidPropertyName(field.getName())) {
      setMethods.put(field.getName(), new SetFieldInvoker(field));
      setTypes.put(field.getName(), field.getType());
    }
  }

  // 木有get方法的属性也是
  private void addGetField(Field field) {
    if (isValidPropertyName(field.getName())) {
      getMethods.put(field.getName(), new GetFieldInvoker(field));
      getTypes.put(field.getName(), field.getType());
    }
  }

  /**
   * 对属性名进行筛选
   * 另外两个我不晓得，但是serialVersionUID确实会出现，这个么得用
   */
  private boolean isValidPropertyName(String name) {
    return !(name.startsWith("$") || "serialVersionUID".equals(name) || "class".equals(name));
  }

  /*
   * 得到所有方法，包括private方法，包括父类方法.包括接口方法,但是不要桥接方法（这玩意是编译器生成的）
   */
  private Method[] getClassMethods(Class<?> cls) {
    Map<String, Method> uniqueMethods = new HashMap<>();
    Class<?> currentClass = cls;
    //这个用了一个while循环,里面是getSuperclass(),这是把父类的方法也都搞出来了
    while (currentClass != null) {
      //1、获取本类中所有声明的方法,包括私有的(private、protected、默认以及public)的方法
      addUniqueMethods(uniqueMethods, currentClass.getDeclaredMethods());
      //2、获取接口方法
      Class<?>[] interfaces = currentClass.getInterfaces();
      for (Class<?> anInterface : interfaces) {
        addUniqueMethods(uniqueMethods, anInterface.getMethods());
      }
      currentClass = currentClass.getSuperclass();
    }
    Collection<Method> methods = uniqueMethods.values();
    return methods.toArray(new Method[0]);
  }

  private void addUniqueMethods(Map<String, Method> uniqueMethods, Method[] methods) {
    for (Method currentMethod : methods) {
      //判断是不是桥接方法，如果是则不去理会
      //理解什么是桥接方法：https://blog.csdn.net/jiaobuchong/article/details/83722193
      //https://www.cnblogs.com/wuqinglong/p/9456193.html
      if (!currentMethod.isBridge()) {
          //取得签名
        String signature = getSignature(currentMethod);
        //这个知道签名是用来去重的
        if (!uniqueMethods.containsKey(signature)) {
          if (canAccessPrivateMethods()) {
            try {
              //使用时取消该方法的访问权限检查
              currentMethod.setAccessible(true);
            } catch (Exception ignored) {}
          }
          uniqueMethods.put(signature, currentMethod);
        }
      }
    }
  }

  /**
   * java中对方法签名的定义,由方法名称和参数列表(方法的参数的顺序和类型)组成。但不包括返回值类型和访问修饰符 ！！！
   * 这里是mybatis自己构造的方法签名
   */
  private String getSignature(Method method) {
    StringBuilder sb = new StringBuilder();
    Class<?> returnType = method.getReturnType();
    if (returnType != null) {
      // 1、添加返回值
      sb.append(returnType.getName()).append('#');
    }
    // 2、添加方法名称
    sb.append(method.getName());
    Class<?>[] parameters = method.getParameterTypes();
    for (int i = 0; i < parameters.length; i++) {
      if (i == 0) {
        sb.append(':');
      } else {
        sb.append(',');
      }
      //3、添加参数名称
      sb.append(parameters[i].getName());
    }
    return sb.toString();
  }

  /**
   *
   * 查看用户是否允许屏蔽对字段和方法的访问权限校验
   * 通常我们没有对这个进行设置，默认是屏蔽的
   *
   */
  private static boolean canAccessPrivateMethods() {
    try {
      SecurityManager securityManager = System.getSecurityManager();
      if (null != securityManager) {
        securityManager.checkPermission(new ReflectPermission("suppressAccessChecks"));
      }
    } catch (SecurityException e) {
      return false;
    }
    return true;
  }

  public boolean hasDefaultConstructor() {
    return defaultConstructor != null;
  }

  public Invoker getSetInvoker(String propertyName) {
    Invoker method = setMethods.get(propertyName);
    if (method == null) {
      throw new ReflectionException("There is no setter for property named '" + propertyName + "' in '" + type + "'");
    }
    return method;
  }

  public Invoker getGetInvoker(String propertyName) {
    Invoker method = getMethods.get(propertyName);
    if (method == null) {
      throw new ReflectionException("There is no getter for property named '" + propertyName + "' in '" + type + "'");
    }
    return method;
  }

  public Class<?> getSetterType(String propertyName) {
    Class<?> clazz = setTypes.get(propertyName);
    if (clazz == null) {
      throw new ReflectionException("There is no setter for property named '" + propertyName + "' in '" + type + "'");
    }
    return clazz;
  }

  public Class<?> getGetterType(String propertyName) {
    Class<?> clazz = getTypes.get(propertyName);
    if (clazz == null) {
      throw new ReflectionException("There is no getter for property named '" + propertyName + "' in '" + type + "'");
    }
    return clazz;
  }


  public String[] getGetablePropertyNames() {
    return readablePropertyNames;
  }


  public String[] getSetablePropertyNames() {
    return writeablePropertyNames;
  }


  public boolean hasSetter(String propertyName) {
    return setMethods.containsKey(propertyName);
  }


  public boolean hasGetter(String propertyName) {
    return getMethods.containsKey(propertyName);
  }

  public String findPropertyName(String name) {
    return caseInsensitivePropertyMap.get(name.toUpperCase(Locale.ENGLISH));
  }

  public static  boolean isClassCacheEnabled(){
    return classCacheEnabled;
  }

  public static void setClassCacheEnabled(boolean classCacheEnabled){
    Reflector.classCacheEnabled = classCacheEnabled;
  }
}
