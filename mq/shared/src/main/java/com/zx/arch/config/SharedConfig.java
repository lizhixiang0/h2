package com.zx.arch.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author admin
 */
@Configuration
@ComponentScan(value={
        "com.zx.arch"
})
public class SharedConfig {
}
