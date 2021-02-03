package com.zx.arch.io;

import lombok.Data;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 将一大堆的规则放大一个文件里去
 **/
@Data
public class CollectRules {

    private static Stream<String> stream;

    private static Long count = 0L ;

    private static Set<String> loadSource = new TreeSet<>();

    private static HashMap<String,Character> rulesName = new HashMap<>();


    public static void main(String[] args) throws URISyntaxException{
        readAllFilesName();
        stream.forEach(i-> {
            try {
                readThenWrite(i);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        System.out.println("rule总条数:"+count);
        loadSource.forEach(System.out::println);

    }

    private static void readAllFilesName() throws URISyntaxException {
        Path p = Paths.get(CollectRules.class.getResource("/static/rulesets").toURI());
        File file = p.toFile();
        String[] fileNames = file.list();
        assert fileNames != null;
        stream = Arrays.stream(fileNames).map(i -> p.toString().concat("\\") + i);
    }

    private static void  readThenWrite(String location) throws IOException {
        Path srcPath = Path.of(location);
        Path destPath = Path.of("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\android_rules.yar");
        AtomicBoolean isUseful = new AtomicBoolean(false);
        String tag = "*/";
        String prefix  = "import";
        String checkString = "droidbox";
        AtomicBoolean ischecked = new AtomicBoolean(true);
        System.out.println(Files.lines(srcPath).count());
        Files.lines(srcPath).forEach(i-> {
            if(i.trim().contains("{")){
                count++;
            }
            //过滤掉'*/'之前的内容
            if(tag.equals(i.trim())){
                isUseful.set(true);
            }
            //一旦出现droidbox则不许写入
            if(i.contains(checkString)){
                ischecked.set(false);
            }
            //过滤空行
            //过滤备注
            //过滤*/
            if(isUseful.get() && ischecked.get()&& !"".equals(i.trim())&&!tag.equals(i.trim())&&!i.trim().startsWith("//")){
                if(i.trim().startsWith(prefix)){
                    loadSource.add(i);
                }else {
                    try {
                        Files.writeString(destPath,dealWithRuleName(i).concat("\r\n"),StandardOpenOption.CREATE,StandardOpenOption.APPEND);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });
        //最后将每个rule分开
        Files.writeString(destPath,"\r\n\r\n",StandardOpenOption.CREATE,StandardOpenOption.APPEND);
    }

    /**
     * rule koodous : official_0
     * rule koodous : official_1
     * 如果名字重复了,按照顺序后面加_?
     */
    public static String dealWithRuleName(String content){
        String prefix = "rule";
        String tag = ":";

        // 如果开头不是rule那不管
        if(!content.trim().startsWith(prefix)){
            return content;
        }else {
            content = content.trim();
            int offset  = content.indexOf(tag);
            if(offset>-1){
                char[] src = content.toCharArray();
                String ruleName = new String(src,content.indexOf(prefix)+prefix.length(),offset-prefix.length()).trim();
                boolean isHas = rulesName.containsKey(ruleName);
                Character suffix = rulesName.get(ruleName);
                if(isHas){
                    rulesName.put(ruleName, (char) (suffix.charValue()+1));
                }else{
                    rulesName.put(ruleName, 'a');
                }
                suffix = rulesName.get(ruleName);
                StringBuilder string  = new StringBuilder();
                string.append(src,0,content.indexOf(ruleName)+ruleName.length());
                return suffix==null?content:string.append("_").append(suffix).append(content.substring(offset)).toString();
            }else{
                String ruleName = content.substring(4).replace("{","").trim();
                boolean isHas = rulesName.containsKey(ruleName);
                Character suffix = rulesName.get(ruleName);
                if(isHas){
                    rulesName.put(ruleName,(char) (suffix.charValue()+1));
                }else{
                    rulesName.put(ruleName, 'a');
                }
                suffix = rulesName.get(ruleName);
                //拿出的值拼装后返回
                return suffix==null?content:content.replace(ruleName,ruleName.concat("_").concat(String.valueOf(suffix)));
            }
        }
    }

    //过滤哪些没啥用的

   /* public static void main(String[] args) {
        String str1 =  dealWithRuleName(" rule adware : installer");
        String str2 =  dealWithRuleName("rule  adware:aggressive");
        String str5 =  dealWithRuleName("rule  adware :aggressive");
        String str3 =  dealWithRuleName("rule adware");
        String str4 =  dealWithRuleName("rule adware : ads");
        String str6 = dealWithRuleName("rule adware {");


        System.out.println(str1);
        System.out.println(str2);
        System.out.println(str5);
        System.out.println(str3);
        System.out.println(str4);
        System.out.println(str6);
    }*/

}
