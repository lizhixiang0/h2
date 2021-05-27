package com.zx.arch.designer.chain.v5;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * 链条中的filter需要有控制链条停止的能力，实现方法就是放filter方法返回布尔类型,满足条件就返回true,不满足返回false!
 * 然后调用链执行时检查filter返回值,一旦出现返回false的,调用链也返回false ,循环就结束了。。

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
    boolean doFilter(Msg m);
}

/**
 * 1、处理html
 */
class HTMLFilter implements Filter {
    @Override
    public boolean doFilter(Msg m) {
        String r = m.getMsg();
        r = r.replace('<', '[');
        r = r.replace('>', ']');
        m.setMsg(r);
        return true;
    }
}

/**
 * 2、处理敏感字
 */
class SensitiveFilter implements Filter {
    @Override
    public boolean doFilter(Msg m) {
        String r = m.getMsg();
        r = r.replaceAll("996", "955");
        m.setMsg(r);
        return true;
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
    public boolean doFilter(Msg m) {
        for(Filter f : filters) {
            if (!f.doFilter(m)){
                return false;
            };
        }
        return true;
    }
}