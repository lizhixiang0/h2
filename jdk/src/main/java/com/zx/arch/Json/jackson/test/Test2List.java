package com.zx.arch.Json.jackson.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zx.arch.Json.jackson.JsonUtils;
import com.zx.arch.Json.jackson.entity.ManifestAnalyse;

import java.lang.reflect.Array;
import java.util.*;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class Test2List {
    private static String KEY = "manifest_analysis";
    private static String MOCK_STRING_LIST =
            "{"+
                    " \"manifest_analysis\": [\n" +
                    "        {\n" +
                    "            \"title\": \"Clear text traffic is Enabled For App<br>[android:usesCleartextTraffic=true]\",\n" +
                    "            \"stat\": \"high\",\n" +
                    "            \"desc\": \"The app intends to use cleartext network traffic, such as cleartext HTTP, FTP stacks, DownloadManager, and MediaPlayer. The default value for apps that target API level 27 or lower is \\\"true\\\". Apps that target API level 28 or higher default to \\\"false\\\". The key reason for avoiding cleartext traffic is the lack of confidentiality, authenticity, and protections against tampering; a network attacker can eavesdrop on transmitted data and also modify it without being detected.\",\n" +
                    "            \"name\": \"Clear text traffic is Enabled For App [android:usesCleartextTraffic=true]\",\n" +
                    "            \"component\": []\n" +
                    "        },\n" +
                    "        {\n" +
                    "            \"title\": \"App has a Network Security Configuration<br>[android:networkSecurityConfig]\",\n" +
                    "            \"stat\": \"info\",\n" +
                    "            \"desc\": \"The Network Security Configuration feature lets apps customize their network security settings in a safe, declarative configuration file without modifying app code. These settings can be configured for specific domains and for a specific app. \",\n" +
                    "            \"name\": \"App has a Network Security Configuration [android:networkSecurityConfig]\",\n" +
                    "            \"component\": []\n" +
                    "        }" +
                    "]"+
            "}";

    private static void toListByJsonUtil(){
        Map<String, Object> jsonMap = JsonUtils.toMap(MOCK_STRING_LIST);
        List<ManifestAnalyse> manifestList =  JsonUtils.toJavaObjectList(jsonMap.get(KEY), ManifestAnalyse.class);
        System.out.println(manifestList.size());
    }

    private static void toListByOriginalMethod() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> jsonMap = objectMapper.readValue(MOCK_STRING_LIST,LinkedHashMap.class);
        //可以将任何java对象序列化成json字符串,和readValue相对，哪个是把json字符串反序列化成java对象
        String string= objectMapper.writeValueAsString(jsonMap.get(KEY));
        //获取对应类的集合类型，没搞懂
        JavaType javaType = objectMapper.getTypeFactory().constructParametricType(List.class, ManifestAnalyse.class);
        List<ManifestAnalyse> list  = objectMapper.readValue(string,javaType);
        System.out.println(list.size());


    }

    public static void main(String[] args) throws JsonProcessingException {
        //toListByJsonUtil();
        toListByOriginalMethod();
    }
}
