package rest;

import com.example.h2.H2Application;
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
    public void testBook() throws Exception {
        Assert.assertThat(this.restTemplate.getForObject("http://localhost:" + port + "/hello",String.class),
                Matchers.containsString("date"));
    }
}
