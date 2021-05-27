package com.zx.arch.designer.chain.v2;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * 抽象出一个Filter类,里面有一个doFilter方法，然后创建不同的实现类，然后集中处理
 * @author lizx
 * @since 1.0.0
 **/
public class Main {
    public static void main(String[] args) {
        Msg msg = new Msg("大家好:)，<script>，欢迎访问 mashibing.com ，大家都是996 ");

        // 处理数据
        List<Filter> filters = new ArrayList<>();
        filters.add(new HTMLFilter());
        filters.add(new SensitiveFilter());

        for(Filter f : filters) {
            f.doFilter(msg);
        }

        System.out.println(msg);

    }
}

@Data
@AllArgsConstructor
class Msg {
    String msg;
}

/**
 * 抽象出一个过滤器,层层过滤，对数据进行处理
 */
interface Filter {
    void doFilter(Msg m);
}

/**
 * 1、处理html
 */
class HTMLFilter implements Filter {
    @Override
    public void doFilter(Msg m) {
        String r = m.getMsg();
        r = r.replace('<', '[');
        r = r.replace('>', ']');
        m.setMsg(r);
    }
}

/**
 * 2、处理敏感字
 */
class SensitiveFilter implements Filter {
    @Override
    public void doFilter(Msg m) {
        String r = m.getMsg();
        r = r.replaceAll("996", "955");
        m.setMsg(r);
    }
}