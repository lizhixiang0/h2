package com.zx.arch.designer.chain.v1;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @author lizx
 * @since 1.0.0
 * @description  论坛发消息,后台需要经过信息处理才会允许存入数据库或者发表，如果想进一步处理，需要改动源代码
 **/
public class Main {
    public static void main(String[] args) {
        Message msg = new Message("大家好:)，<script>，欢迎访问 mashibing.com ，大家都是996 ");

        // 进行信息处理
        String r  = msg.getMsg();
        r = r.replace('<', '[');
        r = r.replace('>', ']');
        r = r.replaceAll("996", "955");
        r = r.replace(":)", "^V^");
        r = r.replace("mashibing.com", "http://www.mashibing.com");
        msg.setMsg(r);

        System.out.println(msg);
    }
}

/**
 * 消息类
 */
@Data
@AllArgsConstructor
class Message {
    String msg;
}
