package com.zx.arch.Json.jackson.test;

import com.zx.arch.Json.jackson.JsonUtils;
import com.zx.arch.Json.jackson.entity.PermissionAnalyse;

import java.util.LinkedHashMap;
import java.util.Map;


/**
 * @author lizx
 * @since 1.0.0
 * @description 将map类型的字符串转化成对象集合（Map）
 * @note 注意字符串必须要{} 包裹，不然会报错    not close json text, token : :
 **/
public class Test01 {
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

    public static void main(String[] args) {
        Map<String, Object> jsonMap = JsonUtils.toMap(mock_map_string);
        Object a = jsonMap.get("permissions");
        Map<String, PermissionAnalyse> permissionMaps = JsonUtils.convertToMap((LinkedHashMap)a, PermissionAnalyse.class);
        System.out.println(permissionMaps.size());
    }
}
