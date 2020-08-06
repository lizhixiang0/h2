package com.zx.arch.kfk.producer;

import com.example.h2.kfk.message.UpdateApkFileMessage;
import com.example.h2.kfk.share.topic.TopicNames;
import org.springframework.stereotype.Component;

/**
 * @author lizx
 * @date 2020/07/20
 **/
@Component
public class ApkFileServiceGatewayImpl extends AbstractKafkaGateway  {
    public void updateApkFileDownloadUrl(UpdateApkFileMessage message) {
        message.setMessageId(messageIdGenerator.generator());
        getKafkaTemplate().send(TopicNames.T_APP_SCAN_EVENT, message);
    }
}
