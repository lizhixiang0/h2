package com.example.h2.kfk.message;

import lombok.Data;
import org.apache.kafka.common.protocol.Message;

/**
 * @author lizx
 * @date 2020/07/20
 **/
@Data
public class UpdateApkFileMessage extends AbstractMessage {
    private static final long serialVersionUID = -3429599001107605552L;
    private Long apkFileId;
    private Long scanTaskId;
}
