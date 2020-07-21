package com.example.h2.kfk.share.serializer;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import java.util.Map;

import org.apache.kafka.common.serialization.Deserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author admin
 */
public class KryoObjDeserializer implements Deserializer<Object> {
    private static final Logger log = LoggerFactory.getLogger(KryoObjDeserializer.class);

    public KryoObjDeserializer() {
    }

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
    }

    @Override
    public Object deserialize(String topic, byte[] data) {
        if (data == null) {
            return null;
        } else {
            if (log.isDebugEnabled()) {
                log.info("Topic: [{}], message size: [{}]", topic, data.length);
            }

            return KryoSerializer.INSTANCE.deserialize(data);
        }
    }

    @Override
    public void close() {
    }
}
