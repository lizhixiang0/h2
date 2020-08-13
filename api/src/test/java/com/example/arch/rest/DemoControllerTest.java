package com.example.arch.rest;

import com.zx.arch.H2Application;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author lizx
 * @date 2020/06/28
 * @description  测试controller层
 * @note  如果配置了test包里配置了application文件，那此处会以test包的为准
 **/
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration(classes = {H2Application.class})
public class DemoControllerTest {

    //使用@LocalServerPort将端口注入进来
    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void testBook(){
        Assert.assertThat(this.restTemplate.getForObject("http://localhost:" + port + "/api/test",String.class),
                Matchers.containsString("s"));
    }
}
