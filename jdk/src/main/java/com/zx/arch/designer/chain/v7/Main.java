package com.zx.arch.designer.chain.v7;

import lombok.AllArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * 控制处理request和response的顺序，先处理request,再处理response
 * 即
 *      request先过HTMLFilter再过SensitiveFilter,
 *      然后response过SensitiveFilter，再过HTMLFilter
 *
 * 方法：在filterChain中处理加入位置的记录,同时在filter中加入第三个参数
 *      
 */
public class Main {
    public static void main(String[] args) {
        Request request = new Request("大家好:)，<script>，欢迎访问 mashibing.com ，大家都是996 ");
        Response response = new Response("response");

        FilterChain chain = new FilterChain();
        chain.add(new HTMLFilter()).add(new SensitiveFilter());
        chain.doFilter(request, response, chain);

        System.out.println(request.str);
        System.out.println(response.str);

    }
}

interface Filter {
    boolean doFilter(Request request, Response response, FilterChain chain);
}
@AllArgsConstructor
class Request {
    String str;
}
@AllArgsConstructor
class Response {
    String str;
}

class HTMLFilter implements Filter {
    @Override
    public boolean doFilter(Request request, Response response, FilterChain chain) {
        request.str = request.str.replaceAll("<", "[").replaceAll(">", "]") + "HTMLFilter()";
        chain.doFilter(request, response, chain);
        response.str += "--HTMLFilter()";
        return true;
    }
}

class SensitiveFilter implements Filter {
    @Override
    public boolean doFilter(Request request, Response response, FilterChain chain) {
        request.str = request.str.replaceAll("996", "955") + " SensitiveFilter()";
        chain.doFilter(request, response, chain);
        response.str += "--SensitiveFilter()";
        return true;
    }
}


class FilterChain implements Filter {
    List<Filter> filters = new ArrayList<>();
    int index = 0;

    public FilterChain add(Filter f) {
        filters.add(f);
        return this;
    }

    @Override
    public boolean doFilter(Request request, Response response, FilterChain chain) {
        if(index == filters.size()) {
            return false;
        }
        Filter f = filters.get(index);
        index ++;

        return f.doFilter(request, response, chain);
    }
}