package com.zx.arch.Json.jackson.entity;

import lombok.Data;

/**
 * @author  lizx
 * @since   1.0.0
 * @date    2020/07/09
 **/
@Data
public class Certification {

    private String description;
    /**
     * @description 状态四种:good 、bad 、miss 、warning
     */
    private String  certificate_status;

    private String  certificate_info;

}
