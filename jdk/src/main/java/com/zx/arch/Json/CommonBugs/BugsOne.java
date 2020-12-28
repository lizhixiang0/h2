package com.zx.arch.Json.CommonBugs;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;

/**
 * @author lizx
 * @since 1.0.0
 * @description JSON序列化导致Long类型被搞成Integer经典巨坑
 * @blog "https://blog.csdn.net/w605283073/article/details/90941038
 **/
public class BugsOne {
    public static void main(String[] args) throws JsonProcessingException {
        String id = "id";
        String name = "name";
        Long idValue = 2147483647L;

        System.out.println(Integer.MAX_VALUE);
        System.out.println(idValue);

        Map<String, Object> data = new HashMap<>(2);
        data.put(id, idValue);
        data.put(name, "张三");

        // 第一步、没序列化时取出id值与原来的id值比较
        Object idObj1 = data.get(id);
        System.out.println(idValue.equals(data.get(id)));
        System.out.println(idObj1 instanceof Long);

        // 第二步、进行JSON序列化
        // 这个是fastjson的序列化，是有这个问题的,
        // String jsonString = JSON.toJSONString(data);
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonString = objectMapper.writeValueAsString(data);

        // 第三步、反序列化后取出id值与原来的id值比较,发现Long被转为了Integer
        //Map map = JSON.parseObject(jsonString, Map.class);
        Map map = objectMapper.readValue(jsonString, Map.class);
        Object idObj = map.get(id);
        System.out.println(idObj instanceof Integer);
        System.out.println(idObj);

        //问题所在:序列化为Json时后，Josn串是没有 Long类型的，而且反转回来也是Object接收，如果数字小于Interger的最大值，就给转成了Integer！
        // 如果大于Interger的最大值,则还是Long类型 ,我是不知道这个是啥问题。
        // 可能是调用方觉得这应该是Long类型，结果被转换成了Integer类型,所以会报类型转换错误。
        // 无论是fastJson 和 jackSon 都有这个问题，或者不是问题，算是一种现象，实际使用使用时出现类型转换错误心里有数即可
        // 避免方法： 1、使用jdk自带的序列化流   2、使用强对象
    }
}
