/*
 *    Copyright 2009-2013 the original author or authors.
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
package org.apache.ibatis.binding;

import lombok.Getter;
import lombok.Setter;
import org.apache.ibatis.annotations.MapKey;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.SqlSession;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.*;

/**
 * Dao层方法的代理方法，调用Dao层的方法都相当于在调用本类的execute方法
 * @author Clinton Begin
 * @author Eduardo Macarron
 * @author Lasse Voss
 */
public class MapperMethod {
  /**
   * SQL命令，静态内部类、 封装了SQL类型 `insert` `update` `delete` `select`
   */
  private final SqlCommand command;

  /**
   * 方法签名，静态内部类，封装了方法的参数信息、返回类型等信息
   */
  private final MethodSignature method;

  public MapperMethod(Class<?> mapperInterface, Method method, Configuration config) {
    this.command = new SqlCommand(config, mapperInterface, method);
    this.method = new MethodSignature(config, method);
  }

  /**
   * 进行增删改查，它会根据条件去匹配方法
   */
  public Object execute(SqlSession sqlSession, Object[] args) {
    Object result;
    // a1、判断是不是insert类型
    if (SqlCommandType.INSERT == command.getType()) {
      // a2、获取参数值或者参数值集合
      Object param = method.convertArgsToSqlCommandParam(args);
      // a3、根据方法返回值对sql返回值进行相应处理
      result = rowCountResult(sqlSession.insert(command.getName(), param));
    } else if (SqlCommandType.UPDATE == command.getType()) {
      Object param = method.convertArgsToSqlCommandParam(args);
      result = rowCountResult(sqlSession.update(command.getName(), param));
    } else if (SqlCommandType.DELETE == command.getType()) {
      Object param = method.convertArgsToSqlCommandParam(args);
      result = rowCountResult(sqlSession.delete(command.getName(), param));
      // b1、判断是不是select类型，如果是，需要考虑方法是否传递了结果处理器
    } else if (SqlCommandType.SELECT == command.getType()) {
      // b2、如果方法传递了结果处理器,但方法返回类型为void,返回null
      if (method.returnsVoid() && method.hasResultHandler()) {
        // todo 这一步的目的是为啥？估计有什么特殊作用,在什么情况下。dao层的select方法返回值会特意写成void ？？？
        executeWithResultHandler(sqlSession, args);
        result = null;
        // b3、如果方法返回类型是数组或集合
      } else if (method.returnsMany()) {
        result = executeForMany(sqlSession, args);
        // b4、如果方法返回类型是map
      } else if (method.returnsMap()) {
        result = executeForMap(sqlSession, args);
      } else {
        // b5、这里包含两种情况，一是返回值为void,二是返回值为其他类型
        Object param = method.convertArgsToSqlCommandParam(args);
        result = sqlSession.selectOne(command.getName(), param);
      }
    } else {
      // 找不到SqlCommandType的类型,则抛出异常
      throw new BindingException("Unknown execution method for: " + command.getName());
    }
    // 假如方法返回值定义为基本类型,且非void ,则当result为null时会抛出异常，所以会通常我们Dao层不要用基本类型当返回值类型
    if (result == null && method.getReturnType().isPrimitive() && !method.returnsVoid()) {
      throw new BindingException("Mapper method '" + command.getName()+ " attempted to return null from a method with a primitive return type (" + method.getReturnType() + ").");
    }
    return result;
  }

  /**
   * 这个方法对返回值的类型进行了一些检查,然后对sql执行的返回值做相应的处理,
   * 主要是将基本类型转化为包装类型。
   */
  private Object rowCountResult(int rowCount) {
    final Object result;
    // 1、方法返回值为void ,就不管rowCount了,直接返回null,
    if (method.returnsVoid()) {
      result = null;
    } else if (Integer.class.equals(method.getReturnType()) || Integer.TYPE.equals(method.getReturnType())) {
      // 2、如果返回值是大int或小int,则返回rowCount的Integer包装类型
      result = Integer.valueOf(rowCount);
    } else if (Long.class.equals(method.getReturnType()) || Long.TYPE.equals(method.getReturnType())) {
      //如果返回值是大long或小long,则返回rowCount的Long包装类型
      result = Long.valueOf(rowCount);
    } else if (Boolean.class.equals(method.getReturnType()) || Boolean.TYPE.equals(method.getReturnType())) {
      //如果返回值是大boolean或小boolean,则返回rowCount的Boolean包装类型
      result = Boolean.valueOf(rowCount > 0);
    } else {
      throw new BindingException("Mapper method '" + command.getName() + "' has an unsupported return type: " + method.getReturnType());
    }
    return result;
  }

  /**
   * 如果方法里参数列表有结果处理器,但返回值为void,则执行此方法
   */
  private void executeWithResultHandler(SqlSession sqlSession, Object[] args) {
    // 1、根据方法全限定名获得sql语句映射器
    MappedStatement ms = sqlSession.getConfiguration().getMappedStatement(command.getName());
    // 2、如果sql语句映射器内部的返回值类型为void,则此处抛出异常
    if (void.class.equals(ms.getResultMaps().get(0).getType())) {
      // 2.1、仔细看异常内容,本方法需要一个@ResultMap注解，或者在xml中定义resultType参数，这样方法里传递ResultHandler才有意义
      throw new BindingException("method " + command.getName()+ " needs either a @ResultMap annotation, a @ResultType annotation," + " or a resultType attribute in XML so a ResultHandler can be used as a parameter.");
    }
    // 3、如果sql语句映射器内部的返回值类型不为void,则执行查询
    Object param = method.convertArgsToSqlCommandParam(args);
    // 4、看看方法参数列表里有没有分页处理器
    if (method.hasRowBounds()) {
      // 4.1、从参数中拿到RowBounds
      RowBounds rowBounds = method.extractRowBounds(args);
      // 4.2、执行查询
      sqlSession.select(command.getName(), param, rowBounds, method.extractResultHandler(args));
    } else {
      // 5、没有分页处理器则直接查询
      sqlSession.select(command.getName(), param, method.extractResultHandler(args));
    }
  }

  /**
   * 返回类型是数组或集合,执行查询
   */
  private <E> Object executeForMany(SqlSession sqlSession, Object[] args) {
    List<E> result;
    // 1、处理下参数
    Object param = method.convertArgsToSqlCommandParam(args);
    // 2、判断是否有分页处理器
    if (method.hasRowBounds()) {
      // 2.1、有,则获取并执行查询
      RowBounds rowBounds = method.extractRowBounds(args);
      result = sqlSession.selectList(command.getName(), param, rowBounds);
    } else {
      // 2.2、没有分页处理器就直接查询
      result = sqlSession.selectList(command.getName(), param);
    }
    // 3、查询后,处理result，一般result返回值为list
    // 3.1、如果方法返回值不是result的父类或同类
    if (!method.getReturnType().isAssignableFrom(result.getClass())) {
      // 3.1.1、如果返回值是数组,则需要将集合转化成数组
      if (method.getReturnType().isArray()) {
        return convertToArray(result);
      } else {
        // 3.1.2、如果返回值是集合,但是是result的子类,或者压根么关系，那就需要强制转化成声明的集合
        return convertToDeclaredCollection(sqlSession.getConfiguration(), result);
      }
    }
    // 3.2、方法返回值是result的父类或同类，则直接返回result
    return result;
  }

  /**
   * 将list集合转化成方法声明的返回值类型
   */
  private <E> Object convertToDeclaredCollection(Configuration config, List<E> list) {
    Object collection = config.getObjectFactory().create(method.getReturnType());
    MetaObject metaObject = config.newMetaObject(collection);
    metaObject.addAll(list);
    return collection;
  }

  @SuppressWarnings("unchecked")
  /**
   * 将集合转化成数组
   */
  private <E> E[] convertToArray(List<E> list) {
    E[] array = (E[]) Array.newInstance(method.getReturnType().getComponentType(), list.size());
    array = list.toArray(array);
    return array;
  }

  /**
   * 方法返回类型是map,执行查询
   */
  private <K, V> Map<K, V> executeForMap(SqlSession sqlSession, Object[] args) {
    Map<K, V> result;
    // 1、处理下参数
    Object param = method.convertArgsToSqlCommandParam(args);
    // 2、判断是否有分页处理器
    if (method.hasRowBounds()) {
      RowBounds rowBounds = method.extractRowBounds(args);
      result = sqlSession.<K, V>selectMap(command.getName(), param, method.getMapKey(), rowBounds);
    } else {
      result = sqlSession.<K, V>selectMap(command.getName(), param, method.getMapKey());
    }
    return result;
  }

  /**
   * 静态内部类，判断当前方法在Configuration有没有对应的MappedStatement，然后获取MappedStatement的id和SqlCommandType
   */
  @Setter
  @Getter
  public static class SqlCommand {
    /**
     * 当前方法的全限定名
     * eq:  com.mybatis.lizx.dao.PersonDao.getById
     */
    private final String name;
    /**
     * 当前方法对应的sql语句类型
     */
    private final SqlCommandType type;

    public SqlCommand(Configuration configuration, Class<?> mapperInterface, Method method) {
      // 1、语句名 = 接口名+方法名,eq: com.mybatis.lizx.dao.PersonDao.getById
      String statementName = mapperInterface.getName() + "." + method.getName();
      // 2、定义映射sql语句引用，这玩意就表示sql语句
      MappedStatement ms = null;
      // 3、判断配置类中是否有该映射sql语句
      if (configuration.hasStatement(statementName)) {
        // 3.1、有则直接获取
        ms = configuration.getMappedStatement(statementName);
      }
      // 4、没有则判断这个方法的声明类是不是当前接口，可能是父类接口声明的
      else if (!mapperInterface.equals(method.getDeclaringClass().getName())) {
        // 4.1 获取方法的声明类名和方法名，构造新的语句名
        String parentStatementName = method.getDeclaringClass().getName() + "." + method.getName();
        // 4.2 判断配置类中是否有该映射sql语句
        if (configuration.hasStatement(parentStatementName)) {
          // 4.3 有则直接获取
          ms = configuration.getMappedStatement(parentStatementName);
        }
      }
      if (ms == null) {
        // 5、如果始终找不到映射语句则抛出异常
        throw new BindingException("Invalid bound statement (not found): " + statementName);
      }
      // 6、找到了映射sql语句，则初始化name 和 type
      name = ms.getId();
      type = ms.getSqlCommandType();
      // 7、如果该映射sql语句的类型是unknown则抛出异常
      if (type == SqlCommandType.UNKNOWN) {
        throw new BindingException("Unknown execution method for: " + name);
      }
    }
  }

  /**
   * 静态内部类，解析当前方法
   */
  public static class MethodSignature {
    // 判断返回类型是不是数组或集合
    private final boolean returnsMany;
    // 判断返回类型是不是Map
    private final boolean returnsMap;
    // 判断返回类型是不是void
    private final boolean returnsVoid;
    // 方法的返回类型
    private final Class<?> returnType;
    // 如果method上有@MapKey注解,表示给注解的value,有这个值说明返回值是Map类型
    private final String mapKey;
    // 判断方法中存在参数前是否加了@Param
    private final boolean hasNamedParameters;
    // 方法中如果有RowBounds类型的参数，表示该参数位置
    private final Integer resultHandlerIndex;
    // 方法中如果有ResultHandler类型的参数,表示该参数位置
    private final Integer rowBoundsIndex;
    // 获得当前方法的参数列表,存储形式是<参数在参数列表中的位置,参数代号>,不包括RowBounds和ResultHandler,
    private final SortedMap<Integer, String> params;


    public MethodSignature(Configuration configuration, Method method) {
      this.returnType = method.getReturnType();
      this.returnsVoid = void.class.equals(this.returnType);
      this.returnsMany = (configuration.getObjectFactory().isCollection(this.returnType) || this.returnType.isArray());
      this.mapKey = getMapKey(method);
      this.returnsMap = (this.mapKey != null);
      this.hasNamedParameters = hasNamedParams(method);
      // 记下RowBounds是第几个参数
      this.rowBoundsIndex = getUniqueParamIndex(method, RowBounds.class);
      // 记下ResultHandler是第几个参数
      this.resultHandlerIndex = getUniqueParamIndex(method, ResultHandler.class);
      // 获得当前方法的参数列表,不包括RowBounds和ResultHandler,unmodifiableSortedMap()方法用于返回指定有序映射的不可修改视图。
      this.params = Collections.unmodifiableSortedMap(getParams(method, this.hasNamedParameters));
    }

    /**
     * 将参数数组解析成想要的样子返回
     * 这个是使用Object当作泛型，要么返回参数值，要么返回HashMap<参数代号,参数值>
     */
    public Object convertArgsToSqlCommandParam(Object[] args) {
      // 1、获得当前方法的参数数量
      final int paramCount = params.size();
      if (args == null || paramCount == 0) {
        // 1.1 没参数没直接返回null
        return null;
        // 1.2 如果只有一个参数且方法中不存在@Param注解，直接返回参数值,这里直接返回args[0]不好吗?
      } else if (!hasNamedParameters && paramCount == 1) {
        return args[params.keySet().iterator().next()];
      } else {
        // 1.3 如果不止一个参数或者方法中存在@Param注解，则返回new HashMap<参数代号,参数值>,比较特殊的使用了自定义的ParamMap来继承HashMap,改写了get方法
        // 注意:ParamMap里面的参数代号储存了三种表示形式,一种是使用0,1等整数,另一种是使用"param1","param2" ,最后一种是@Param,那就直接是@Param的value
        final Map<String, Object> param = new ParamMap<>();
        int i = 0;
        for (Map.Entry<Integer, String> entry : params.entrySet()) {
          // 1.3.1 第一种、使用0,1等整数 和 第三种、使用@Param的value
          param.put(entry.getValue(), args[entry.getKey()]);
          // 1.3.2 第二种,使用 param1、。。。
          final String genericParamName = "param" + (i + 1);
          if (!param.containsKey(genericParamName)) {
            param.put(genericParamName, args[entry.getKey()]);
          }
          i++;
        }
        return param;
      }
    }

    public boolean hasRowBounds() {
      return rowBoundsIndex != null;
    }

    public RowBounds extractRowBounds(Object[] args) {
      return hasRowBounds() ? (RowBounds) args[rowBoundsIndex] : null;
    }

    public boolean hasResultHandler() {
      return resultHandlerIndex != null;
    }

    public ResultHandler extractResultHandler(Object[] args) {
      return hasResultHandler() ? (ResultHandler) args[resultHandlerIndex] : null;
    }

    public String getMapKey() {
      return mapKey;
    }

    public Class<?> getReturnType() {
      return returnType;
    }

    public boolean returnsMany() {
      return returnsMany;
    }

    public boolean returnsMap() {
      return returnsMap;
    }

    public boolean returnsVoid() {
      return returnsVoid;
    }

    /**
     * 获得特殊类型参数的位置
     * 特殊参数：RowBounds.class、ResultHandler.class
     * 真的没几个人会直接在Dao层接口方法里传这个参数。。。
     */
    private Integer getUniqueParamIndex(Method method, Class<?> paramType) {
      Integer index = null;
      final Class<?>[] argTypes = method.getParameterTypes();
      for (int i = 0; i < argTypes.length; i++) {
        if (paramType.isAssignableFrom(argTypes[i])) {
          if (index == null) {
            index = i;
          } else {
            throw new BindingException(method.getName() + " cannot have multiple " + paramType.getSimpleName() + " parameters");
          }
        }
      }
      return index;
    }

    /**
     * eq:
     *     '@MapKey("id")
     *     '@ResultMap("BaseResultMap")
     *     '@Select("select * from user where hotel_address = #{address};")
     *     Map<Long, User> getUserByAddress(@Param("address") String address);
     */
    private String getMapKey(Method method) {
      String mapKey = null;
      // 1、判断返回值是否是map类型，不是则返回null
      if (Map.class.isAssignableFrom(method.getReturnType())) {
        // 1.1 如果是查看该method是否有MapKey注解。没有返回null
        final MapKey mapKeyAnnotation = method.getAnnotation(MapKey.class);
        if (mapKeyAnnotation != null) {
          // 1.2 如果有这个注解，将这个注解的值作为mapKey
          mapKey = mapKeyAnnotation.value();
        }
      }

      return mapKey;
    }

    /**
     * 判断方法参数上有没有加@Param注解,加了返回true
     * "@Param"是作为Dao层的注解，作用是用于传递参数，从而可以与SQL中的的字段名相对应，一般在2=<参数数<=5时使用最佳.
     * eq:
     *     ScanEngineDetail getScanEngineDetailByIdentifier(@Param("identifier") String identifier);
     */
    private boolean hasNamedParams(Method method) {
      boolean hasNamedParams = false;
      // getParameterAnnotations()得到的结果是一个二维数组，因为一个参数前可以添加多个注解
      final Object[][] paramAnnos = method.getParameterAnnotations();
      for (Object[] paramAnno : paramAnnos) {
        for (Object aParamAnno : paramAnno) {
          if (aParamAnno instanceof Param) {
            hasNamedParams = true;
            break;
          }
        }
      }
      return hasNamedParams;
    }

    /**
     * 获得所有参数,需要的是<参数位置,参数代号>,所以选择<k,v>的存储结构
     * 再加上得有序，最终选择了TreeMap
     * TreeMap 默认按照keys的自然排序排列,对Integer来说,其自然排序就是数字的升序;对String来说,其自然排序就是按照字母表排序
     * 其实LinkedHashMap也可以实现有序,但是这里没用。
     */
    private SortedMap<Integer, String> getParams(Method method, boolean hasNamedParameters) {
      // 1、创建TreeMap
      final SortedMap<Integer, String> params = new TreeMap<>();
      // 2、获得方法的所有参数
      final Class<?>[] argTypes = method.getParameterTypes();
      // 3、遍历
      for (int i = 0; i < argTypes.length; i++) {
        // 3.1、只有该参数既不是RowBounds也不是ResultHandler才进行处理（这两种参数是单独拿出来的）
        if (!RowBounds.class.isAssignableFrom(argTypes[i]) && !ResultHandler.class.isAssignableFrom(argTypes[i])) {
          // 3.1.1 参数名字默认是按顺序用0,1,2来指代，所以xml里面可以用#{1}这样的写法来表示参数，这边很巧妙,直接用TreeMap.size()来实现+1
          // 其实按我心里想的，直接String paramName = i 最省事
          String paramName = String.valueOf(params.size());
          // 3.1.2 如果该方法存在参数加了@Parm注解,那就看看是不是该参数,如果是就用@Parm的value表示参数名
          if (hasNamedParameters) {
            //3.1.2.1 从注解中获取value来表示参数名,如果不是该参数加了@Parm，那还是返回原来的paramName
            paramName = getParamNameFromAnnotation(method, i, paramName);
          }
          // 如果没有@Param, key和value应该是相等的
          params.put(i, paramName);
        }
      }
      return params;
    }

    /**
     * @param method 当前方法
     * @param i 当前参数在方法参数列表中的位置
     * @param paramName  如果是当前参数前加的@Param，那就取出其value赋值给paramName返回，不是就直接返回
     */
    private String getParamNameFromAnnotation(Method method, int i, String paramName) {
      final Object[] paramAnnos = method.getParameterAnnotations()[i];
      for (Object paramAnno : paramAnnos) {
        if (paramAnno instanceof Param) {
          paramName = ((Param) paramAnno).value();
        }
      }
      return paramName;
    }
  }

  /**
   * 静态内部类
   * HashMap的get方法，找不到就返回null,所以这里搞了个子类,重写了get方法，如果没有相应的key,抛出异常
   */
  public static class ParamMap<String,V> extends HashMap<String, V> {
    private static final long serialVersionUID = -1L;
    @Override
    public V get(Object key) {
      if (!super.containsKey(key)) {
        throw new BindingException("Parameter '" + key + "' not found. Available parameters are " + keySet());
      }
      return super.get(key);
    }
  }
}
