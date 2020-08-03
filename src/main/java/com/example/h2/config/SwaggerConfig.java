package com.example.h2.config;

import com.google.common.base.Predicates;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * @author admin
 * @author lizx
 * @date 2020/07/27
 **/
@Configuration
@ConditionalOnProperty(name = "swagger.enabled", havingValue = "true")
@EnableSwagger2 //配置这个就可以直接访问swagger了   http://localhost:8084/swagger-ui.html
public class SwaggerConfig {



    @Value("${application.version}")
    private String version;

    /**
     * Docket是swagger的实例bean,配置docket就是配置Swagger
     * @return
     */
    @Bean
    public Docket docket(Environment environment) {
        // 设置要显示swagger的环境,比如dev环境才显示test
        Profiles of = Profiles.of("dev", "test");
        // 判断当前是否处于该环境
        boolean flag = environment.acceptsProfiles(of);

        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(getApiInfo("APIs for Test"))
                // 1、配置是否启用Swagger
                .enable(!flag)
                // 2、配置分组，第一组
                .groupName("Test-API")
                // 3、配置扫描包路径
                .select()
                .apis(RequestHandlerSelectors.basePackage(basePackage()))
                // 4、只扫描请求以/test开头的接口,这里用的ant()
                .paths(PathSelectors.ant("/test/**"))
                .build();
    }
    /**
     * 第一组是test组，第二组是其他组(排除test)
     * @return
     */
    @Bean
    public Docket paxstoreApi() {
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName("Other-api")
                .select()
                .apis(RequestHandlerSelectors.basePackage(basePackage()))
                // 这个匹配规则比较特殊，test如果在类上就是/test.* , 在方法上就是/test/*
                .paths(Predicates.and(Predicates.not(PathSelectors.regex("/test.*"))))
                .build()
                .apiInfo(getApiInfo("APIs for Others"));
    }

    /**
     * 在@Configuration配置文件里，除非是从yml文件里取出的属性，其他的不要定义成成员变量
     * @return
     */
    private String basePackage() {
        return "com.example.h2.rest";
    }

    /**
     * ApiInfo这个对象是swagger的内置对象，专门用来自定义swagger文档信息的
     * @param title
     * @return
     */
    private ApiInfo getApiInfo(String title) {
        return new ApiInfoBuilder()
                .title(title)
                .version(version)
                .description("HTTP Status Code:" +
                        "\n- 200: The request has succeeded. The information returned with the response is dependent on the method used in the request" +
                        "\n- 201: The request has been fulfilled and resulted in a new resource being created" +
                        "\n- 204: The server has fulfilled the request but does not need to return an entity-body" +
                        "\n- 400: The request could not be understood by the server due to malformed syntax" +
                        "\n- 401: The request requires user authentication" +
                        "\n- 403: The server understood the request, but is refusing to fulfill it" +
                        "\n- 404: The server has not found anything matching the Request-URI" +
                        "\n- 409: The request could not be completed due to a conflict with the current state of the resource" +
                        "\n- 500: The server encountered an unexpected condition which prevented it from fulfilling the request")
                .build();
    }


}
