package com.zx.arch.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author lizx
 * @date 2020/08/31
 * @description  Spring Security 是 Spring 家族中的一个安全管理框架
 *               Spring Boot 对于 Spring Security 提供了 自动化配置方案，可以零配置使用 Spring Security
 * @blog         https://blog.csdn.net/yuanlaijike/category_9283872.html
 **/
@Configuration
@EnableWebSecurity  //加上这个注解即可以零配置使用 Spring Security
public class CustomSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     *
     * @param auth
     * @throws Exception
     * 配置了两个用户a和b,密码都是a
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("a").roles("admin").password("$2a$10$qg3RRldr/BBIf23MrpdACerj5ZXd.EVnuDIkS72Ys.UMqJcwT3Bsi")
                .and()
                .withUser("b").roles("user").password("$2a$10$qg3RRldr/BBIf23MrpdACerj5ZXd.EVnuDIkS72Ys.UMqJcwT3Bsi");
    }

    /**
     * 注入了一个BCryptPasswordEncoder类,实现Spring的PasswordEncoder接口使用BCrypt强哈希方法来加密密码
     * @return
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }






}
