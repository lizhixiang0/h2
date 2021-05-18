package com.zx.arch.config;

import com.zx.arch.spring.filter.FilterTest;
import com.zx.arch.spring.filter.FilterTwo;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

/**
 * @author lizx
 * @since 1.0.0
 * @descripiton 使用SpringSecurity
 * @note
 *       虽然我们在WebMvcConfigurer中设置跨域，但是如果WebSecurityConfigurerAdapter中不设置http.cors()，会导致一个的问题：
 *       如果一个需要被spring security过滤器验证的请求，比如对url“/getInfo”的请求，如果这个请求没有通过验证，
 *       比如没有携带token或token不正确，导致没有给该请求发放authentication，
 *       那么这个请求会在后续的Authentication过滤器中被认定鉴权失败，直接返回response给客户端。
 *       这种情况下请求将不会交给WebMvcConfigurer的跨域过滤器，
 *       而WebMvcConfigurer的跨域过滤器会给response header中添加“Access-Control-Allow-Origin”字段，
 *       该字段表示服务器接收此Origin的跨域请求。由于该请求不会经过WebMvcConfigurer的过滤器，
 *       因此响应头中不会携带“Access-Control-Allow-Origin”字段，导致虽然请求正确在服务器处理了，也把响应发回给浏览器了，
 *       但是浏览器认为服务器不接受该地址的跨域请求，不会将response传递给页面脚本，并且提示该服务器禁止此Origin的跨域请求。
 * @link "
 **/
/*@Configuration
@EnableWebSecurity*/
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String[] PUBLIC_URLS = new String[]{
            "/**"};

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.headers().frameOptions().disable().and()
                .csrf().disable().cors().and()  //NOSONAR
                .exceptionHandling()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).sessionFixation().none()
                .and()
                .authorizeRequests().requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .antMatchers(PUBLIC_URLS).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(new FilterTwo(),
                        UsernamePasswordAuthenticationFilter.class);
    }
}
