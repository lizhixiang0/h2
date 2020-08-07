package com.zx.arch.serializer;


import org.apache.kafka.common.serialization.Serializer;

import java.util.Map;

/**
 * @author admin
 */
public class KryoObjSerializer implements Serializer<Object> {
    public KryoObjSerializer() {
    }

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
    }

    @Override
    public byte[] serialize(String topic, Object data) {
        return KryoSerializer.INSTANCE.serialize(data);
    }

    @Override
    public void close() {
    }
}
