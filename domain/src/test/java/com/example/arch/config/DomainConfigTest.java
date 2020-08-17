package com.example.arch.config;

import com.alibaba.druid.pool.DruidDataSource;
import org.flywaydb.core.Flyway;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.io.File;
import java.net.URISyntaxException;

/**
 * @author lizx
 * @date 2020/08/13
 **/
@Configuration
@ComponentScan(basePackages = "com.zx.arch.domain")
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class})
@MapperScan("com.zx.arch.domain.dao")
public class DomainConfigTest {

    @Value("${spring.datasource.driver-class-name}")
    private String driverClassname;
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String username;
    @Value("${spring.datasource.password}")
    private String password;
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
    public DruidDataSource datasource() {
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
     * @param dataSource
     * @return
     * @description   这里是通过注入bean的方式来执行里面的代码，让flyway执行api模块的sql文件，将数据存储到h2内存数据库中。
     * @note    写demo的时候不需要配置数据源,但是现在需要配置，不然找不到DataSource !,通过上面的德鲁伊连接池配置的数据源。
     */
    @Bean
    public Object DbFixture(DataSource dataSource) {
        File folder = null;
        try {
            folder = new File(DomainConfigTest.class.getResource("/").toURI().getPath().replace("/domain/target/test-classes/", "/api/src/main/resources/"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        assert folder != null;
        String prefix = "filesystem:" + folder.getAbsolutePath();
        Flyway.configure()
                .dataSource(dataSource)
                .baselineOnMigrate(true)
                .locations(prefix+"/db/migration/common")
                .load()
                .migrate();
        return null;
    }
}
