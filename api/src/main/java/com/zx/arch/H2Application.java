package com.zx.arch;

import com.zx.arch.auth.config.CustomSecurityConfig;
import com.zx.arch.domain.config.DomainConfig;
import com.zx.arch.spring.life.BeanLifeCycle;
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
       // System.setProperty("tomcat.util.http.parser.HttpParser.requestTargetAllow","! * ’ ( ) ; : @ & = + \"\"$ , / ? # [ ]{}");
    }

    @Bean(initMethod = "myInitMethod", destroyMethod = "myDestroyMethod")
    public BeanLifeCycle getBeanLifeCycle(){
        BeanLifeCycle beanLifeCycle = new BeanLifeCycle();
        beanLifeCycle.setAge(1);
        return beanLifeCycle;
    }

}
