package com.zx.arch.config;

import com.alibaba.fastjson.support.config.FastJsonConfig;
import com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter;
import com.zx.arch.handler.CustomHandlerExceptionResolver;
import com.zx.arch.il8.AppScanApiLocaleResolver;
import com.zx.arch.spring.filter.FilterTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @author lizx
 * @date 2020/07/01
 * @description spring mvc 配置
 **/
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    /**
     *
     * @param converters 一、消息转换器
     * @description
     * SpringMVC中，可以使用@RequestBody和@ResponseBody两个注解，分别完成请求报文到对象和对象到响应报文的转换，
     * 底层是利用HttpMessageConverter来实现的！
     * Spring内置了很多HttpMessageConverter，比如 MappingJackson2HttpMessageConverter，StringHttpMessageConverter等，
     * 我们可以定义自己的消息转换器
     * 有两种方式：
     *       a、配置spring或者第三方(如fastJson)提供的现成的HttpMessageConverter，然后替换
     *       b、自己重写一个HttpMessageConverter。写完注册到容器直接生效
     *          博客:https://www.cnblogs.com/hhhshct/p/9676604.html
     */
    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        FastJsonHttpMessageConverter fastJsonHttpMessageConverter = new FastJsonHttpMessageConverter();
        //配置输出的时间格式为yyyy-MM-dd
        FastJsonConfig fastJsonConfig = new FastJsonConfig();
        fastJsonConfig.setCharset(Charset.forName("UTF-8"));
        fastJsonConfig.setDateFormat("yyyy-MM-dd");
        fastJsonHttpMessageConverter.setFastJsonConfig(fastJsonConfig);
        //配置输出Media类型为json格式
        List<MediaType> list = new ArrayList<>();
        list.add(MediaType.APPLICATION_JSON);
        fastJsonHttpMessageConverter.setSupportedMediaTypes(list);

        /*converters.add(fastJsonHttpMessageConverter);*/
        /*这里说明下spring已经内置了FastJsonHttpMessageConverter,所以不能直接add,而是替换原来的*/
        for(int i = 0;i<converters.size();i++){
            if(converters.get(i) instanceof MappingJackson2HttpMessageConverter){
                converters.set(i,fastJsonHttpMessageConverter);
            }
        }
    }

    @Bean
    public Converter addConverters(){
        return new Converter<String, Date>() {
            @Override
            public Date convert(String source) {
                DateFormat format = null;
                try {
                    if(StringUtils.isEmpty(source)) {
                        throw new NullPointerException("请输入要转换的日期");
                    }
                    format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                    Date date = format.parse(source);
                    return date;} catch (Exception e) {
                    throw new RuntimeException("输入日期有误");

                }
            }
        };
    }



    /**
     * @param exceptionResolvers 二、全局异常处理
     * @description
     * 后端应用出现异常时，通常会将异常状况包装之后再返回给调用方或者前端
     * 在实际的项目中，不可能对每一个地方都做好异常处理，通常是使用spring的全局异常处理
     * 有两种方式:
     *          a、@Controller和 @ExceptionHandler结合
     *          b、自定义 HandlerExceptionResolver来对异常进行处理
     *
     */
   @Override
    public void configureHandlerExceptionResolvers(List<HandlerExceptionResolver> exceptionResolvers) {
        exceptionResolvers.add(new CustomHandlerExceptionResolver());
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowCredentials(true)
                .allowedOrigins("*")
                .allowedHeaders("*")
                .allowedMethods("*");
    }

    @Bean
    public CustomHandlerExceptionResolver errorHandler(){
        return new CustomHandlerExceptionResolver();
    }

    @Bean(name = "localeResolver")
    public LocaleResolver localeResolver() {
        return new AppScanApiLocaleResolver();
    }

    /**
     * 注册filter
     * @return
     */
    /*@Bean
    public FilterRegistrationBean myFilterRegistrationBean(){
        //注册过滤器
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean(new FilterTest());
        //添加过滤路径
        filterRegistrationBean.addUrlPatterns("/*");
        return filterRegistrationBean;
    }*/

}
