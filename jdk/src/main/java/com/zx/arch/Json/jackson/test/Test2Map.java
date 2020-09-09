package com.zx.arch.Json.jackson.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Maps;
import com.zx.arch.Json.jackson.JsonUtils;
import com.zx.arch.Json.jackson.entity.PermissionAnalyse;
import org.apache.commons.collections.MapUtils;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;


/**
 * @author lizx
 * @since 1.0.0
 * @description 将map类型的字符串转化成对象集合（Map）
 * @note 注意字符串必须要{} 包裹，不然会报错    not close json text, token : :
 **/
public class Test2Map {
    private static String KEY_OF_MAP = "permissions";
    private static String mock_map_string =
            "{"+
                " \"permissions\": " +"{" +
                        "\"com.baihe.bp.permission.C2D_MESSAGE\": " + "{" +
                                "\"status\": \"signature\"," +
                                "\"info\": \"Allows cloud to device messaging\"," +
                                "\"description\": \"Allows the application to receive push notifications.\"" +
                        "}," +
                        "\"android.permission.WRITE\": " + "{" +
                                "\"status\": \"dangerous\"," +
                                "\"info\": \"Unknown permission from android reference\"," +
                                "\"description\": \"Unknown permission from android reference\"" +
                         "}," +
                        "\"android.permission.CAMERA\": {" +
                                "\"status\": \"dangerous\"," +
                                "\"info\": \"take pictures and videos\"," +
                                "\"description\": \"Allows application to take pictures and videos with the camera. This allows the application to collect images that the camera is seeing at any time.\"" +
                         "}" +
                 "}"+
            "}";

    public static void useOriginalMethod() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, LinkedHashMap> jsonMap = objectMapper.readValue(mock_map_string,LinkedHashMap.class);
        Map<String, PermissionAnalyse> permissionMaps = Maps.newHashMap();
        LinkedHashMap linkedHashMap = jsonMap.get(KEY_OF_MAP);
        linkedHashMap.keySet().forEach(i->{
            permissionMaps.put(i.toString(),objectMapper.convertValue(linkedHashMap.get(i),PermissionAnalyse.class));
        });
        System.out.println("original" + "\r\n"+permissionMaps.size());
    }
    public static void useJsonUtil(){
        //将json格式的字符串转化成map集合
        Map<String, Object> jsonMap = JsonUtils.toMap(mock_map_string);
        //取出对应的value值,将其转化成map格式
        Map<String, PermissionAnalyse> permissionMaps = JsonUtils.convertToMap((LinkedHashMap)jsonMap.get(KEY_OF_MAP), PermissionAnalyse.class);
        System.out.println("JsonUtils" + "\r\n"+permissionMaps.size());
    }

    public static void main(String[] args) throws JsonProcessingException {
        // 使用jackson 原生方法
        useOriginalMethod();
        // 使用jackson utils ,使用方便，对异常做出了try catch 处理,并且可以对ObjectMapper做定制化处理，好处多多,建议使用!
        useJsonUtil();
    }

}
