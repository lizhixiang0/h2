package com.zx.arch.io;

import com.zx.arch.Json.jackson.entity.ManifestAnalyse;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import com.pax.support.resttemplate.RESTUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;

/**
 * @author lizx
 * @since 1.0.0
 * @description 从网上获取rule
 *              https://api.koodous.com/public_rulesets?page=84
 *              https://api.koodous.com/public_rulesets/2552
 **/
public class GetRulesFromWeb {

    public static void main(String[] args) {
        for(int i = 1;i<85;i++){
            int finalI = i;
            new Thread(()->{
                parse(connect("https://api.koodous.com/public_rulesets?page=".concat(String.valueOf(finalI))));
            }).start();
        }

    }

    public static String connect(String url){
        RestTemplate restTemplate = RESTUtils.getNoneSingletonRestTemplate(10000, 10000, 10000, false, 3, 100, 20, null);
        ResponseEntity<String> res = restTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                String.class);
        return  res.getBody();
    }

    public static void parse(String data){
        Map<String, Object> jsonMap = JsonUtils.toMap(data);
        assert jsonMap != null;
        List<RuleInfo> manifestList =  JsonUtils.toJavaObjectList(jsonMap.get("results"), RuleInfo.class);
        manifestList.forEach(i-> {
            try {
                String rule  = i.getRules();
                if(!rule.contains("file.md5") && !rule.contains("droidbox.")){
                    write(i.getRules().concat("\r\n"));
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    public static  void write(String rule) throws IOException {
        Path destPath = Path.of("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\rulesets\\all_rules.yar");
        Files.writeString(destPath,rule, StandardOpenOption.CREATE,StandardOpenOption.APPEND);
    }
}
