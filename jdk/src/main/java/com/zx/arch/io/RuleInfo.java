package com.zx.arch.io;

import lombok.Data;

/**
 * @author lizx
 * @since 1.0.0
 **/
@Data
public class RuleInfo {
    private String id;
    /**
     * 病毒特征码名
     */
    private String name;
    /**
     * 侦测数
     */
    private String detections;
    /**
     * 是否激活
     */
    private boolean active;

    private String rules;
}
