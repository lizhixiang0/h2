package com.zx.arch.designer.chain.v4;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * 调用链也实现filter抽象类，这样做可以将调用链也当做一个filter处理器

 * @author lizx
 * @since 1.0.0
 **/
public class Main {
    public static void main(String[] args) {
        Msg msg = new Msg("大家好:)，<script>，欢迎访问 mashibing.com ，大家都是996 ");

        // 处理数据
        FilterChain fc = new FilterChain();
        fc.add(new HTMLFilter());


        FilterChain fc2 = new FilterChain();
        fc2.add(new SensitiveFilter());


        fc.add(fc2);
        fc.doFilter(msg);

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

/**
 * 集中处理filter
 */
class FilterChain implements Filter {
    private List<Filter> filters = new ArrayList<>();

    public FilterChain add(Filter f) {
        filters.add(f);
        return this;
    }

    @Override
    public void doFilter(Msg m) {
        for(Filter f : filters) {
            f.doFilter(m);
        }
    }
}