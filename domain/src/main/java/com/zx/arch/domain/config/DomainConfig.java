package com.zx.arch.domain.config;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;



/**
 * @author admin
 * @author lizx
 * @date 2020/08/17
 * @description 配置domain模块并且由启动类通过import导入项目
 * @Note    1、直接加@Configuration ,api模块的启动类识别不到！！没法import进去,需要先import，然后再@Configuration
 *          2、@MapperScan将包下所有的都注解成Mapper,加了这个才能被api模块捕捉到
 * **/
@Configuration
@ComponentScan(basePackages = "com.zx.arch.domain.service")
@MapperScan("com.zx.arch.domain.dao")
public class DomainConfig {
    /**
     * 这四个属性，配置在application.yml文件里
     */
    @Value("${spring.datasource.driver-class-name}")
    private String driverClassname;
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String username;
    @Value("${spring.datasource.password}")
    private String password;
    /**
     * 这里直接默认值，使用的德鲁伊连接池
     */
    @Value("${spring.datasource.jdbc.testSql: SELECT 'x' FROM DUAL}")
    private String testSQL;
    @Value("${spring.datasource.jdbc.pool.init:1}")
    private int poolInitSize;
    @Value("${spring.datasource.jdbc.pool.min-idle:3}")
    private int minIdle;
    @Value("${spring.datasource.jdbc.pool.max-active:20}")
    private int maxActive;
    @Value("${spring.datasource.jdbc.pool.max-wait:60000}")
    private long maxWait;

    @Bean(initMethod = "init", destroyMethod = "close")
    public DruidDataSource datasource(){
        DruidDataSource ds = new DruidDataSource();
        ds.setDriverClassName(driverClassname);
        ds.setUrl(url);
        ds.setUsername(username);
        ds.setPassword(password);
        ds.setInitialSize(poolInitSize);
        ds.setMinIdle(minIdle);
        ds.setMaxActive(maxActive);
        ds.setMaxWait(maxWait);
        ds.setTimeBetweenEvictionRunsMillis(300000);
        ds.setValidationQuery(testSQL);
        ds.setTestWhileIdle(true);
        ds.setTestOnBorrow(false);
        ds.setTestOnReturn(false);
        return ds;
    }

    /**
     *
     * @return
     * @throws Exception
     * @description 配置会话工厂
     */
    @Bean
    public SqlSessionFactory sqlSessionFactory() throws Exception {
        SqlSessionFactoryBean sqlSessionFactory = new SqlSessionFactoryBean();
        //配置数据源
        sqlSessionFactory.setDataSource(datasource());
        //设置映射文件地址
        sqlSessionFactory.setMapperLocations(
                new PathMatchingResourcePatternResolver().getResources("classpath:mappings/*Mapper.xml"));
        return sqlSessionFactory.getObject();
    }

}
