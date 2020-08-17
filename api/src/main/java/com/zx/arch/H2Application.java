package com.zx.arch;

import com.zx.arch.domain.config.DomainConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

/**
 * @author admin
 */
@SpringBootApplication
@Import({DomainConfig.class,
})
public class H2Application {
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(H2Application.class);
        //app.addListeners(new ApplicationPidFileWriter("app.pid"));
        app.run(args);
    }
}
