package com.zx.arch.designer.chain.v6;

import java.util.ArrayList;
import java.util.List;

/**
 * 过滤两个类,一个request,一个response
 */
public class Main {
    public static void main(String[] args) {
        Request request = new Request();
        request.str = "大家好:)，<script>，欢迎访问 mashibing.com ，大家都是996 ";
        Response response = new Response();
        response.str = "response";

        FilterChain chain = new FilterChain();
        chain.add(new HTMLFilter()).add(new SensitiveFilter());
        chain.doFilter(request, response);
        System.out.println(request.str);
        System.out.println(response.str);

    }
}

interface Filter {
    boolean doFilter(Request request, Response response);
}

class Request {
    String str;
}

class Response {
    String str;
}

class HTMLFilter implements Filter {
    @Override
    public boolean doFilter(Request request, Response response) {
        request.str = request.str.replaceAll("<", "[").replaceAll(">", "]");
        response.str += "--HTMLFilter()";
        return true;
    }
}

class SensitiveFilter implements Filter {
    @Override
    public boolean doFilter(Request request, Response response) {
        request.str = request.str.replaceAll("996", "955");
        response.str += "--SensitiveFilter()";
        return true;
    }
}


class FilterChain implements Filter {
    List<Filter> filters = new ArrayList<>();

    /**
     * 这里用了个小技巧,builder方式
     * @param f
     * @return
     */
    public FilterChain add(Filter f) {
        filters.add(f);
        return this;
    }

    @Override
    public boolean doFilter(Request request, Response response) {
        for(Filter f : filters ){
            f.doFilter(request, response);
        }
        return true;
    }
}