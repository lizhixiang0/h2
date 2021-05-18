package com.zx.arch.spring.filter;


import org.springframework.stereotype.Component;

import javax.servlet.*;
import java.io.IOException;

/**
 * @author lizx
 * @since 1.0.0
 * @description 使用过滤器 "https://blog.csdn.net/qq_36976201/article/details/115279184
 *               为什么有OncePerRequestFilter？        “https://blog.csdn.net/u013089490/article/details/84878319
 *               注入方式有很多： https://blog.csdn.net/p812438109/article/details/107827059
 * @note 使用@WebFilter则必须使用FilterRegistrationBean注入，使用@Component则不需要，但是此时无法配置路径
 * @note 全局统一异常处理无法拦截FILTER中CATCH的异常 "https://www.freesion.com/article/7691642390/
 * @note filter原理 https://zhuanlan.zhihu.com/p/260027763
 **/

//@WebFilter(value = "/*", filterName = "oauthFilter")
    @Component
public class FilterTest implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("ssss1");
        chain.doFilter(request, response);
        System.out.println("ssss2");
    }

    @Override
    public void destroy() {

    }
}
