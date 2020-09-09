package com.zx.arch.Json.jackson.entity;

import lombok.Data;

/**
 * @author  lizx
 * @since   1.0.0
 * @date    2020/06/19
 **/
@Data
public class ManifestAnalyse {
    /**
     * @description  三种状态: high 、info 、medium
     */
    private String stat;
    private String[] component;
    private String name;
    private String title;
    private String desc;

}
