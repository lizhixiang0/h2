package com.example.arch.serviceTest;

import com.example.arch.config.DomainConfigTest;
import com.zx.arch.domain.entity.User;
import com.zx.arch.domain.service.impl.UserServiceImpl;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

/**
 * @author lizx
 * @date 2020/08/13
 * @description mvc分层思想，service层测试和controller层测试分开
 **/
@SpringBootTest
@ContextConfiguration(classes = { DomainConfigTest.class })
public class H2Test {

    @Autowired
    UserServiceImpl userServiceImpl;


    @Test
    public void insertTest() {
        User user = userServiceImpl.getUserById(1L);
        assert user!=null;
    }

}