package com.zx.arch;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author admin
 */
@SpringBootApplication
public class H2Application {
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(H2Application.class);
        //app.addListeners(new ApplicationPidFileWriter("app.pid"));
        app.run(args);
    }
}
