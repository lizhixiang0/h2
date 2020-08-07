package com.zx.arch.topic;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author lizx
 * @date 2020/07/20
 **/
@Component
public class DefaultTopicBeanProvider implements TopicBeanProvider, ApplicationContextAware {

    @Value("${kafka.consumer.group-id}")
    private String consumerGroupId;
    @Override
    public List<String> getTopicNames() {
        return TopicNames.BIZ_TOPIC_NAME_LIST;
    }

    @Override
    public List<String> getJsonTopicNames() {
        return TopicNames.JSON_TOPIC_NAME_LIST;
    }

    @Override
    public String getConsumerGroupId() {
        return consumerGroupId;
    }

    @Override
    public String getConsumerContainerFactoryBeanSuffix() {
        return "_cf";
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        consumerGroupId = applicationContext.getEnvironment().getProperty("kafka.consumer.group-id");
    }
}



