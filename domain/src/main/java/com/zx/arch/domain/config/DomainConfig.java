package com.zx.arch.domain.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;



/**
 * @author lizx
 * @date 2020/08/17
 * @description 配置domain模块并且由启动类通过import导入项目
 * @Note    直接加@Configuration ,api模块的启动类识别不到！！没法import进去,需要先import，然后再@Configuration**/
@Configuration
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class})
@ComponentScan(basePackages = "com.zx.arch.domain")
//在配置类里加扫描注解的意思是将这个包下所有的都注解成Mapper
@MapperScan("com.zx.arch.dao")
public class DomainConfig {
}
