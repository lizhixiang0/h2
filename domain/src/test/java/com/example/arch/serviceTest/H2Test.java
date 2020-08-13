package com.example.arch.serviceTest;

import com.example.arch.config.DomainConfigTest;
import com.zx.arch.entity.User;
import com.zx.arch.service.impl.UserServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

/**
 * @author lizx
 * @date 2020/08/13
 * @description 我第一次真正懂什么叫mvc分层思想，原来service层测试和controller层测试根本无关
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