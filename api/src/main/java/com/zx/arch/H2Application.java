package com.zx.arch;

import com.zx.arch.auth.config.CustomSecurityConfig;
import com.zx.arch.domain.config.DomainConfig;
import com.zx.arch.spring.life.BeanLifeCycle1;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * @author admin
 */
@SpringBootApplication
@Import({
        DomainConfig.class,
        CustomSecurityConfig.class,
})
public class H2Application {
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(H2Application.class);
        //app.addListeners(new ApplicationPidFileWriter("app.pid"));
        app.run(args);
    }

    @Bean(initMethod = "myInitMethod", destroyMethod = "myDestroyMethod")
    public BeanLifeCycle1 setBeanLifeCycle(){
        BeanLifeCycle1 beanLifeCycle1 = new BeanLifeCycle1();
        beanLifeCycle1.setAge(1);
        return beanLifeCycle1;
    }

}
