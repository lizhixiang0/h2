package com.zx.arch.Json.jackson.test;

import com.zx.arch.Json.jackson.JsonUtils;
import com.zx.arch.Json.jackson.entity.Certification;

import java.util.Map;

/**
 * @author lizx
 * @since 1.0.0
 * @description 测试json字符串转化成java对象 {@link java.lang.Object}
 * @note  注意这个json字符串的格式,稍微错了都会报错，就不要犯少逗号这种错了。
 **/
public class Test2JavaObject {
    private static String KEY = "certificate_analysis";
    private static String MOCK_JSON_STRING =
            "{"+
                        "\"certificate_analysis\": {\n" +
                    "        \"certificate_info\": \"APK is signed\\nv1 signature: True\\nv2 signature: False\\nv3 signature: False\\nFound 1 unique certificates\\nSubject: C=cn, ST=gd, L=gz, O=uc, OU=uc, CN=uc\\nSignature Algorithm: rsassa_pkcs1v15\\nValid From: 2011-03-30 06:11:56+00:00\\nValid To: 2065-12-31 06:11:56+00:00\\nIssuer: C=cn, ST=gd, L=gz, O=uc, OU=uc, CN=uc\\nSerial Number: 0x4d92c9ac\\nHash Algorithm: sha1\\nmd5: 51a5eb6e85033f42271535aad119a2f4\\nsha1: 207b2fdd43ef02ff00fa74c932d2c1d863e51452\\nsha256: bbe2ff269828a0d922498ee87f65afe769c27d62f489d5c19b9cc6c444c80811\\nsha512: a8a672b1c3061acae0b3d365382f64bec36b632b3125cd22d6a222619efab8e456ebb977b0998ace27500ff7d1dd550384fa8c73da5b803b19130ea52cd74988\",\n" +
                    "        \"certificate_status\": \"bad\",\n" +
                    "        \"description\": \"The app is signed with SHA1withRSA. SHA1 hash algorithm is known to have collision issues.\"\n" +
                    "    }"+
            "}";

    public static void toJavaObject(){
        Map<String, Object> jsonMap = JsonUtils.toMap(MOCK_JSON_STRING);
        Certification certification = JsonUtils.toJavaObject(jsonMap.get(KEY), Certification.class);
        //其实就是用的mapper.readValue(value, tClass);
        System.out.println(certification.toString());
    }

    public static void main(String[] args) {
        toJavaObject();
    }

}
