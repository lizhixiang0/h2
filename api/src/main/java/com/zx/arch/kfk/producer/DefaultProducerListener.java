package com.zx.arch.kfk.producer;//



import org.apache.kafka.clients.producer.RecordMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.support.ProducerListener;

/**
 * @author admin
 */
public class DefaultProducerListener implements ProducerListener {
    private static final Logger logger = LoggerFactory.getLogger(DefaultProducerListener.class);

    public DefaultProducerListener() {
    }

    @Override
    public void onSuccess(String topic, Integer partition, Object key, Object value, RecordMetadata recordMetadata) {
        logger.debug(">>>Send message success, topic={}, partition={}, ObjectKey={}, ObjectValue={}, recordMetadata={}", new Object[]{topic, partition, key, value, recordMetadata});
    }

    @Override
    public void onError(String topic, Integer partition, Object key, Object value, Exception exception) {
        logger.warn(">>>Send message encounter error, topic={}, partition={}, ObjectKey={}, ObjectValue={}, Exception={}", new Object[]{topic, partition, key, value, exception});
    }
}
