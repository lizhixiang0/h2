package com.zx.arch.config;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * @author admin
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ServiceDeployInfo implements Serializable {
    private static final long serialVersionUID = 4058952630475113653L;
    /**
     * 是否为内联模式
     */
    private boolean deployIntranet;
    /**
     * 互联网地址
     */
    private String internetUrl;
    /**
     * 内联网地址
     */
    private String intranetUrl;
    /**
     * 密钥
     */
    private String secretKey;
}
