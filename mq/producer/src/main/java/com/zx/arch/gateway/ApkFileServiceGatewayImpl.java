package com.zx.arch.gateway;

import com.zx.arch.message.UpdateApkFileMessage;
import com.zx.arch.topic.TopicNames;
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
