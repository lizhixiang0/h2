package com.example.h2.kfk.consumer;

import com.example.h2.kfk.message.UpdateApkFileMessage;
import org.springframework.stereotype.Component;

/**
 * @author lizx
 * @date 2020/07/20
 **/
@Component
public class ApkFileUpdateHandler extends AbstractHandler<UpdateApkFileMessage> {
    @Override
    protected void handleInternal(UpdateApkFileMessage message) {
        System.out.println("我在这里！！！");
    }
}
