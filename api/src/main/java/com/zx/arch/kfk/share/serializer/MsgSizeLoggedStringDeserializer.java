package com.zx.arch.kfk.share.serializer;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author admin
 */
public class MsgSizeLoggedStringDeserializer extends StringDeserializer {
    private static final Logger log = LoggerFactory.getLogger(MsgSizeLoggedStringDeserializer.class);

    public MsgSizeLoggedStringDeserializer() {
    }

    @Override
    public String deserialize(String topic, byte[] data) {
        if (log.isDebugEnabled()) {
            log.info("Topic: [{}], message size: [{}]", topic, data.length);
        }

        return super.deserialize(topic, data);
    }
}
