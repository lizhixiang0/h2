package com.zx.arch.web.swagger.base;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

/**
 * @author lizx
 * @date 2020/08/06
 **/
@Setter
@Getter
@ToString
public class BaseScanTask implements Serializable {
    private Long id;
}
