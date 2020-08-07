package com.zx.arch.kfk.producer;

import com.zx.arch.kfk.message.Message;
import com.zx.arch.kfk.message.MessageIdGenerator;
import com.zx.arch.kfk.share.topic.TopicBeanProvider;
import com.zx.arch.spring.SpringContextHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.kafka.core.KafkaTemplate;


import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author admin
 */
public abstract class AbstractKafkaGateway {
    @Autowired
    @Qualifier("kryoKafkaTemplate")
    private KafkaTemplate<String, Object> kryoKafkaTemplate;
    @Autowired
    @Qualifier("jsonKafkaTemplate")
    private KafkaTemplate<String, String> jsonKafkaTemplate;
    @Autowired
    protected MessageIdGenerator messageIdGenerator;
    private Map<String, TopicBeanProvider> topicBeanProviderMap;

    public AbstractKafkaGateway() {
    }

    protected KafkaTemplate getKafkaTemplate(String topicName) {
        if (this.topicBeanProviderMap == null) {
            this.topicBeanProviderMap = SpringContextHolder.getBeansOfType(TopicBeanProvider.class);
        }

        Iterator beanNameIter = this.topicBeanProviderMap.keySet().iterator();

        List jsonTopicNames;
        do {
            if (!beanNameIter.hasNext()) {
                return this.kryoKafkaTemplate;
            }

            TopicBeanProvider topicBeanProvider = (TopicBeanProvider)this.topicBeanProviderMap.get(beanNameIter.next());
            jsonTopicNames = topicBeanProvider.getJsonTopicNames();
        } while(jsonTopicNames == null || !jsonTopicNames.contains(topicName));

        return this.jsonKafkaTemplate;
    }

    protected KafkaTemplate<String, Object> getKafkaTemplate() {
        return this.kryoKafkaTemplate;
    }

    public void send(String topicName, Message message) {
        message.setMessageId(this.messageIdGenerator.generator());
        this.getKafkaTemplate().send(topicName, message);
    }

    public void send(String topicName, Message message, int partition) {
        message.setMessageId(this.messageIdGenerator.generator());
        this.getKafkaTemplate().send(topicName, partition, null, message);
    }
}
