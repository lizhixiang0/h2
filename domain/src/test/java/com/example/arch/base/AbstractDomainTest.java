package com.example.arch.base;

import com.example.arch.config.DomainConfigTest;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.AbstractTransactionalJUnit4SpringContextTests;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;

/**
 * @author lizx
 * @date 2020/08/13
 **/
@Ignore
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { DomainConfigTest.class })
@TestPropertySource("classpath:application.yml")
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class, DirtiesContextTestExecutionListener.class })
public class AbstractDomainTest extends AbstractTransactionalJUnit4SpringContextTests {
}
