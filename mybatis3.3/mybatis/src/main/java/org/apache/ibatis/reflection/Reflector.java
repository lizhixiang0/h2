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
 * Reflector是整个反射器模块的基础，每个Reflector对象都对应一个类，
 * 在其构造函数中，根据传入的Class对象，调用Java的反射API获取这个类的元信息 (其中会用到缓存)
 * @blog "https://www.jianshu.com/p/cd4a5e3f884c
 * @author Clinton Begin
 */
@Data
public class Reflector {

  /**
   * 默认开启缓存
   */
  private static boolean classCacheEnabled = true;
  /**
   * toArray用的
   */
  private static final String[] EMPTY_STRING_ARRAY = new String[0];

  //这里使用了一个Map来做缓存，注意使用的是ConcurrentHashMap,保证线程安全
  private static final Map<Class<?>, Reflector> REFLECTOR_MAP = new ConcurrentHashMap<>();

  //对应的Class类型
  private Class<?> type;

  //默认构造函数
  private Constructor<?> defaultConstructor;
  //可读属性的名称集合，可读属性就是存在相应getter方法的属性，初始值为空数纽   getName ---> name
  private String[] readablePropertyNames;
  //可写属性的名称集合，可写属性就是存在相应setter方法的属性，初始值为空数纽
  private String[] writeablePropertyNames;
  //属性相应的setter方法，key是属性名称,value是MethodInvoker对象（mybatis实现的Invoker类,实际运行中如将SQL执行返回结果集映射为Java对象，设置对象属性的操作需要反射(Invoker)来完成）
  private Map<String, Invoker> setMethods = new HashMap<>();
  //属性相应的getter方法集合， key是属性名称， value是MethodInvoker对象,通setMethods
  private Map<String, Invoker> getMethods = new HashMap<>();
  //属性相应的setter方法的参数值类型， key是属性名称， value是setter方法的参数类型,不管是执行SQL前参数的预编译，还是执行完之后将结果集映射为Java对象，都需要知道属性的类型
  private Map<String, Class<?>> setTypes = new HashMap<>();
  //属性相应的getter方法的返回位类型， key是属性名称， value是getter方法的返回值类型,通setTypes
  private Map<String, Class<?>> getTypes = new HashMap<>();
  //所有属性名称的集合,key统一记录成大写
  private Map<String, String> caseInsensitivePropertyMap = new HashMap<>();

  /*
   * Gets an instance of ClassInfo for the specified class.
   * 得到某个类的反射器，是静态方法，而且要缓存，又要多线程，所以REFLECTOR_MAP是一个ConcurrentHashMap
   * @param clazz The class for which to lookup the method cache.
   * @return The method cache for the class
   */
  public static Reflector forClass(Class<?> clazz) {
    if (classCacheEnabled) {
      // 这里是使用到缓存的，所以先从缓存中获取，拿不到才去构造
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
    readablePropertyNames = getMethods.keySet().toArray(EMPTY_STRING_ARRAY);
    writeablePropertyNames = setMethods.keySet().toArray(EMPTY_STRING_ARRAY);
    //将上面两个集合中的所有属性名的大写作为key来填充caseInsensitivePropertyMap
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

  /**
   * 筛选出getter方法:
   *          1、一般属性名为aaBb对应的getter方法为getAaBb()，
   *          2、 如果属性是布尔值，则对应的getter方法为isAaBb()
   *          3、另外，如果子类重写覆盖了父类getter方法导致方法签名不一致
   *          eg:
   *            父类定义:  List<String> getList()      方法签名为: java.util.List<String>#getList
   *            子类定义： ArrayList<String> getList() 方法签名为: java.util.ArrayList<String>#getList
   *          我们要取的肯定是返回参数类型更加具体的方法，但是方法签名不一致导致冲突，就先将属性名和对应的冲突方法缓存到conflictingGetters，再交给resolveGetterConflicts()方法进一步处理
   * @param cls class
   */
  private void addGetMethods(Class<?> cls) {
    //定义属性名和对应getter方法的映射，这里<k,v>中v类型取的list
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
    // 收集到所有get()方法信息后开始处理,主要是解决方法名相同签名不同 getter 方法，一般一个方法名只对应一个getter方法
    resolveGetterConflicts(conflictingGetters);
  }

  private void addMethodConflict(Map<String, List<Method>> conflictingMethods, String name, Method method) {
    //就是判断Map有没有这个<k,v> ,没有就创建 ,有就直接操作这个k对应的list
    conflictingMethods.computeIfAbsent(name, k -> new ArrayList<>()).add(method);
  }

  private void resolveGetterConflicts(Map<String, List<Method>> conflictingGetters) {
    //循环遍历Map集合
    for (String propName : conflictingGetters.keySet()) {
      List<Method> getters = conflictingGetters.get(propName);
      Iterator<Method> iterator = getters.iterator();
      Method firstMethod = iterator.next();
      //如果Value里只有一个元素（method），那就直接调用addGetMethod(name,method)方法
      if (getters.size() == 1) {
        addGetMethod(propName, firstMethod);
      }
      //如果同一属性名称存在多个getter方法，则需要对比这些getter方法的返回值（会把父类或者接口的也拿过来，此时需要筛选出当前类属性真正匹配的get方法）
      else {
        // 迭代过程中的临时变量，用于记录迭代到目前为止最适合作为getter方法的Method
        Method getter = firstMethod;
        Class<?> getterType = firstMethod.getReturnType();
        while (iterator.hasNext()) {
          Method method = iterator.next();
          Class<?> methodType = method.getReturnType();
          // 如果两个方法的返回值类型一样则直接抛出异常,因为前面处理过，这里一样肯定是出错了
          if (methodType.equals(getterType)) {throw new ReflectionException("Illegal overloaded getter method with ambiguous type for property " + propName + " in class " + firstMethod.getDeclaringClass() + ".  This breaks the JavaBeans " + "specification and can cause unpredicatble results."); }
          // methodType是getterType的父类或接口，那就不做处理,最适合的还是getterType
          else if (methodType.isAssignableFrom(getterType)) {}
          // methodType是getterType的子类,那就把最适合的变为methodType
          else if (getterType.isAssignableFrom(methodType)) {
            getter = method;
            getterType = methodType;
          }else {
            //如果不同的 getter 只是刚好方法名相同，实际上返回类型既不完全相同，也没有继承派生关系，则证明开发人员写的类不符合 JavaBean 的规范，此时直接抛出异常
            throw new ReflectionException("Illegal overloaded getter method with ambiguous type for property " + propName + " in class " + firstMethod.getDeclaringClass() + ".  This breaks the JavaBeans " + "specification and can cause unpredicatble results."); }
        }
        //while循环结束筛选出最合适的方法之后，调用addGetMethod()方法填充getMethods和getTypes集合
        addGetMethod(propName, getter);
      }
    }
  }

  private void addGetMethod(String name, Method method) {
    // 筛选过滤掉非法的属性名
    if (isValidPropertyName(name)) {
      // 将属性名以及对应的MethodInvoker对象添加到getMethods集合中，MethodInvoker是对Method对象反射操作的封装
      getMethods.put(name, new MethodInvoker(method));
      // 这里如果返回值是泛型会出问题
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
        //查看name对应的get方法返回类型，拿不到抛出异常
        //一个符合 JavaBean 规范的类应该同时有 getter 和 setter，并且 getter 的返回类型和 setter 的参数类型一致；程序先去处理 getter，所以这里先根据属性名从 getTypes 获取到 getter 的返回类型。
        Class<?> expectedType = getTypes.get(propName);
        if (expectedType == null) {
          throw new ReflectionException("Illegal overloaded setter method with ambiguous type for property " + propName + " in class " + firstMethod.getDeclaringClass() + ".  This breaks the JavaBeans " + "specification and can cause unpredicatble results.");
        } else {
          Iterator<Method> methods = setters.iterator();
          Method setter = null;
          while (methods.hasNext()) {
            Method method = methods.next();
            //setter参数个数应该只有一个并且参数类型跟getter方法的返回值类型相同，不符合则循环
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
    // 获取类中声明的所有field属性
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
          // 获取类的修饰符，过滤掉被声明为static final的属性，这些属性只能被类加载器设置其初始值  @blog "https://www.yiibai.com/javareflect/javareflect_field_getmodifiers.html
          int modifiers = field.getModifiers();
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
      //创建封装了属性对应Field对象的SetFieldInvoker对象，内部利用Field的set方法来反射设置属性值
      setMethods.put(field.getName(), new SetFieldInvoker(field));
      setTypes.put(field.getName(), field.getType());
    }
  }

  // 木有get方法的属性也是
  private void addGetField(Field field) {
    if (isValidPropertyName(field.getName())) {
      //创建封装了属性对应Field对象的GetFieldInvoker对象，内部利用Field的get方法来反射获得属性值
      getMethods.put(field.getName(), new GetFieldInvoker(field));
      getTypes.put(field.getName(), field.getType());
    }
  }

  /**
   * 筛选过滤掉非法的属性名
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
    // 在while循环体中解析从cls到cls的父类,包括接口
    while (currentClass != null) {
      //1、获取类内定义的普通方法，包括私有的(private、protected、默认以及public)的方法,对于继承的方法无法通过反射获取,
      addUniqueMethods(uniqueMethods, currentClass.getDeclaredMethods());
      //2、获取接口方法
      Class<?>[] interfaces = currentClass.getInterfaces();
      for (Class<?> anInterface : interfaces) {
        addUniqueMethods(uniqueMethods, anInterface.getMethods());
      }
      //3、获取从父类继承的方法
      currentClass = currentClass.getSuperclass();
    }
    Collection<Method> methods = uniqueMethods.values();
    return methods.toArray(new Method[0]);
  }

  private void addUniqueMethods(Map<String, Method> uniqueMethods, Method[] methods) {
    for (Method currentMethod : methods) {
      //判断是不是桥接方法，过滤掉桥接方法，桥接方法不是类中定义的方法，而是编译器为了兼容自动生成的方法
      //理解什么是桥接方法：https://blog.csdn.net/jiaobuchong/article/details/83722193
      //https://www.cnblogs.com/wuqinglong/p/9456193.html
      if (!currentMethod.isBridge()) {
        // 通过getSignature方法(mybatis自己构造)得到的方法签名是: 返回值类型#方法名称:参数类型列表。
        // 例如，Reflector.getSignature(Method)方法的唯一签名是:
        // java.lang.String#getSignature:java.lang.reflect.Method
        // 通过Reflector.getSignature()方法得到的方法签名是全局唯一的，可以作为该方法的唯一标识
        String signature = getSignature(currentMethod);
        //因为是先传递子类后传父类的方法过来，所以这里的情况是，如果有重复的，代表是子类覆盖的父类的方法，就不要再添加了
        if (!uniqueMethods.containsKey(signature)) {
          if (canAccessPrivateMethods()) {
            try {
              //使用时取消该方法的访问权限检查，这样使用时可以直接invoke
              currentMethod.setAccessible(true);
            } catch (Exception ignored) {}
          }
          //记录该签名和方法的对应关系
          uniqueMethods.put(signature, currentMethod);
        }
      }
    }
  }

  /**
   * java中对方法签名的定义,由方法名称和参数列表(方法的参数的顺序和类型)组成。但不包括返回值类型和访问修饰符 ！！！
   * 这里是mybatis自己构造的方法签名
   * 其组成规则为：方法返回值类型#方法名:参数1类型,参数2类型,参数3类型,...,参数名n类型
   * eg：void#addUniqueMethods:Map<String, Method>,Method[]

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
      // 获取系统安全管理器
      SecurityManager securityManager = System.getSecurityManager();
      // 如果设置了安全管理器，检查是否有通过反射来访问protected、private的成员和方法的权限
      if (null != securityManager) {
        securityManager.checkPermission(new ReflectPermission("suppressAccessChecks"));
      }
    } catch (SecurityException e) {
      // 如果没有权限，则权限检查会抛出异常，返回false表示不允许访问私有方法
      return false;
    }
    // 如果未设置安全管理器，或者有指定权限，则返回true表示允许访问私有方法
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
