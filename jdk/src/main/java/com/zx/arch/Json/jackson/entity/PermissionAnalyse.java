package com.zx.arch.Json.jackson.entity;

import lombok.*;

/**
 * @author lizx
 * @since 1.0.0
 **/
@Data
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
public class PermissionAnalyse {
    /**
     * @description  ÈýÖÖ×´Ì¬ dangerous ¡¢normal ¡¢signature
     */
    private String status;
    private String info;
    private String description;
}