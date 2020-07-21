package com.example.h2.config;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import com.example.h2.kfk.message.DefaultMessageIdGenerator;
import com.example.h2.kfk.message.MessageIdGenerator;
import com.example.h2.kfk.producer.DefaultProducerListener;
import com.example.h2.kfk.share.topic.TopicBeanProvider;
import java.util.HashMap;
import java.util.Map;

import com.example.h2.kfk.share.serializer.KryoObjSerializer;
import org.apache.kafka.common.serialization.IntegerSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

/**
 * @author admin
 */
@Configuration
public class KafkaProducerConfig {
    @Value("${kafka.broker.hosts}")
    private String brokerHosts;
    @Value("${kafka.producer.retries:0}")
    private int retries;
    @Value("${kafka.producer.batch-size:16384}")
    private int batchSize;
    @Value("${kafka.producer.linger-ms:1}")
    private int lingerMills = 1;
    @Value("${kafka.producer.buffer-memory:33554432}")
    private int bufferMemory;
    @Value("${kafka.producer.acks:0}")
    private String acks;

    public KafkaProducerConfig() {
    }

    @Bean(
            name = {"jsonProducerFactory"}
    )
    public ProducerFactory<String, String> jsonProducerFactory() {
        Map<String, Object> props = this.getDefaultProps();
        props.put("value.serializer", JsonSerializer.class);
        return new DefaultKafkaProducerFactory(props);
    }

    @Bean(
            name = {"kryoProducerFactory"}
    )
    public ProducerFactory<String, Object> producerFactory() {
        Map<String, Object> props = this.getDefaultProps();
        props.put("value.serializer", KryoObjSerializer.class);
        return new DefaultKafkaProducerFactory(props);
    }

    private Map<String, Object> getDefaultProps() {
        Map<String, Object> props = new HashMap(10);
        props.put("bootstrap.servers", this.brokerHosts);
        props.put("retries", this.retries);
        props.put("batch.size", this.batchSize);
        props.put("linger.ms", this.lingerMills);
        props.put("buffer.memory", this.bufferMemory);
        props.put("acks", this.acks);
        props.put("key.serializer", IntegerSerializer.class);
        return props;
    }

    @Bean(
            name = {"jsonKafkaTemplate"}
    )
    public KafkaTemplate<String, String> jsonKafkaTemplate() {
        KafkaTemplate kafkaTemplate = new KafkaTemplate(this.jsonProducerFactory());
        kafkaTemplate.setProducerListener(new DefaultProducerListener());
        return kafkaTemplate;
    }

    @Bean(
            name = {"kryoKafkaTemplate"}
    )
    public KafkaTemplate<String, Object> kryoKafkaTemplate() {
        KafkaTemplate kafkaTemplate = new KafkaTemplate(this.producerFactory());
        kafkaTemplate.setProducerListener(new DefaultProducerListener());
        return kafkaTemplate;
    }

    @Bean
    public MessageIdGenerator messageIdGenerator() {
        return new DefaultMessageIdGenerator();
    }
}
