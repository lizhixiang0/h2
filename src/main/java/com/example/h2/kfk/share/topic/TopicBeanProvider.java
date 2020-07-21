package com.example.h2.kfk.share.topic;

import java.util.List;

/**
 * @author lizx
 * @date 2020/07/20
 **/
public interface TopicBeanProvider {
    List<String> getTopicNames();

    List<String> getJsonTopicNames();

    String getConsumerGroupId();

    String getConsumerContainerFactoryBeanSuffix();
}
