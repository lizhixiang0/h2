package config;

import org.flywaydb.core.Flyway;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.io.File;
import java.net.URISyntaxException;

/**
 * @author lizx
 * @date 2020/06/24
 **/
@Configuration
@ComponentScan(basePackages = "com.example.h2")
public class DomainConfigTest {
    @Bean
    public Object DbFixture(DataSource dataSource) {
        File folder = null;
        try {
            folder = new File(DomainConfigTest.class.getResource("/").toURI().getPath().replace("/target/test-classes/", "/src/main/resources/"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        assert folder != null;
        String sql_location = "filesystem:" + folder.getAbsolutePath()+"/db/migration";
        File  file = new File(sql_location);
        Boolean b = file.exists();
        Flyway.configure()
                .dataSource(dataSource)
                .baselineOnMigrate(true)
                .locations(sql_location)
                .load()
                .migrate();
        return null;
    }
}
