package com.example.arch.config;

import com.alibaba.druid.pool.DruidDataSource;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.io.File;
import java.net.URISyntaxException;
import java.sql.SQLException;

/**
 * @author lizx
 * @date 2020/08/13
 **/
@Configuration
@ComponentScan(basePackages = "com.zx.arch")
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
    public DruidDataSource datasource() throws SQLException {
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
     * @description   ������ͨ��ע��bean�ķ�ʽ��ִ������Ĵ��룬��flywayִ��apiģ���sql�ļ��������ݴ洢��h2�ڴ����ݿ��С�
     * @note    дdemo��ʱ����Ҫ��������Դ,����������Ҫ���ã���Ȼ�Ҳ���DataSource !,ͨ������ĵ�³�����ӳ����õ�����Դ��
     */
    @Bean
    public Object DbFixture(DataSource dataSource) {
        File folder = null;
        try {
            folder = new File(DomainConfigTest.class.getResource("/").toURI().getPath().replace("domain/target/test-classes/", "/api/src/main/resources/"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        assert folder != null;
        String sql_location = "filesystem:" + folder.getAbsolutePath()+"/db/migration/common";
        Flyway.configure()
                .dataSource(dataSource)
                .baselineOnMigrate(true)
                .locations(sql_location)
                .load()
                .migrate();
        return null;
    }
}
