package com.zx.arch.domain.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;



/**
 * @author lizx
 * @date 2020/08/17
 * @description ����domainģ�鲢����������ͨ��import������Ŀ
 * @Note    ֱ�Ӽ�@Configuration ,apiģ���������ʶ�𲻵�����û��import��ȥ,��Ҫ��import��Ȼ����@Configuration**/
@Configuration
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class})
@ComponentScan(basePackages = "com.zx.arch.domain")
//�����������ɨ��ע�����˼�ǽ�����������еĶ�ע���Mapper
@MapperScan("com.zx.arch.dao")
public class DomainConfig {
}
