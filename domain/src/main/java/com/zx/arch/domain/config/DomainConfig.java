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
 * @description ����domainģ�鲢����������ͨ��import������Ŀ
 * @Note    1��ֱ�Ӽ�@Configuration ,apiģ���������ʶ�𲻵�����û��import��ȥ,��Ҫ��import��Ȼ����@Configuration
 *          2��@MapperScan���������еĶ�ע���Mapper,����������ܱ�apiģ�鲶׽��
 * **/
@Configuration
@ComponentScan(basePackages = "com.zx.arch.domain.service")
@MapperScan("com.zx.arch.domain.dao")
public class DomainConfig {
    /**
     * ���ĸ����ԣ�������application.yml�ļ���
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
     * ����ֱ��Ĭ��ֵ��ʹ�õĵ�³�����ӳ�
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
     * @description ���ûỰ����
     */
    @Bean
    public SqlSessionFactory sqlSessionFactory() throws Exception {
        SqlSessionFactoryBean sqlSessionFactory = new SqlSessionFactoryBean();
        //��������Դ
        sqlSessionFactory.setDataSource(datasource());
        //����ӳ���ļ���ַ
        sqlSessionFactory.setMapperLocations(
                new PathMatchingResourcePatternResolver().getResources("classpath:mappings/*Mapper.xml"));
        return sqlSessionFactory.getObject();
    }

}
