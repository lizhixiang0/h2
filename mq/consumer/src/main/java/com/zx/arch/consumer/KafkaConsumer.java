package com.zx.arch.consumer;

import com.zx.arch.handle.ApkFileUpdateHandler;
import com.zx.arch.message.UpdateApkFileMessage;
import com.zx.arch.topic.TopicNames;
import org.apache.kafka.clients.consumer.Consumer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * @author lizx
 * @date 2020/07/20
 **/
@Component
public class KafkaConsumer {

    public static final String CONTAINER_FACTORY_BEAN_SUFFIX = "_cf";

    @Autowired
    private ApkFileUpdateHandler apkFileUpdateHandler;

    @KafkaListener(topics = TopicNames.T_APP_SCAN_EVENT,
            containerFactory = TopicNames.T_APP_SCAN_EVENT + CONTAINER_FACTORY_BEAN_SUFFIX)
    public void updateCloudMsgProperties(UpdateApkFileMessage msg, Consumer consumer) {
        apkFileUpdateHandler.handleMessage(msg);
        //consumer.commitSync();
    }
}
