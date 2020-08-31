package com.zx.arch.auth.config;

import com.zx.arch.auth.filter.PaxstoreApiAuthenticationFilter;
import com.zx.arch.auth.handler.DefaultErrorResponseHandler;
import com.zx.arch.auth.token.TokenServiceApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

/**
 * @author lizx
 * @date 2020/08/31
 * @description  Spring Security 是 Spring 家族中的一个安全管理框架
 *               Spring Boot 对于 Spring Security 提供了 自动化配置方案，可以零配置使用 Spring Security
 * @blog         https://blog.csdn.net/yuanlaijike/category_9283872.html
 **/
@Configuration
@EnableWebSecurity  //加上这个注解即可以零配置使用 Spring Security
@ComponentScan("com.zx.arch.auth.token")
public class CustomSecurityConfig extends WebSecurityConfigurerAdapter {

   /* *//**
     *
     * @param auth
     * @throws Exception
     * 配置了两个用户a和b,密码都是a
     *//*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("a").roles("admin").password("$2a$10$qg3RRldr/BBIf23MrpdACerj5ZXd.EVnuDIkS72Ys.UMqJcwT3Bsi")
                .and()
                .withUser("b").roles("user").password("$2a$10$qg3RRldr/BBIf23MrpdACerj5ZXd.EVnuDIkS72Ys.UMqJcwT3Bsi");
    }

    *//**
     * 注入了一个BCryptPasswordEncoder类,实现Spring的PasswordEncoder接口使用BCrypt强哈希方法来加密密码
     * @return
     *//*
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }*/

    /**
     * 公告url,不需要认证
     */
    protected static final String[] PUBLIC_URLS = new String[]{
            "/**",
    };

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                //不支持网页嵌入(iframe)
                .headers().frameOptions().disable().and()
                //基于JWT，关闭csrf跨域伪造保护
                .csrf().disable()
                //支持cors跨域请求
                .cors().and()
                //基于token，关闭session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                //预检请求放行,针对cors复杂请求的预检处理
                .authorizeRequests().requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                //option请求放行
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                //公共url放行
                .antMatchers(PUBLIC_URLS).permitAll()
                //除了上面三个之外都需要认证
                .anyRequest().authenticated()
                .and()
                // 添加JWT filter
                //.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
                .addFilterBefore(paxstoreApiAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    }

    /*@Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationTokenFilter();
    }*/
    @Autowired
    private TokenServiceApi tokenServiceApi;

    protected static final String[] API_NEED_CURRENT_SERVICE_ENABLED_URLS = new String[] {
            "/api/pax/abc"
    };

    public PaxstoreApiAuthenticationFilter paxstoreApiAuthenticationFilter(){
        return new PaxstoreApiAuthenticationFilter(PUBLIC_URLS,new DefaultErrorResponseHandler(), API_NEED_CURRENT_SERVICE_ENABLED_URLS, tokenServiceApi);
    }
}
