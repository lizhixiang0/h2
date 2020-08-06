package com.zx.arch.web.swagger.request;

import com.zx.arch.web.swagger.base.BaseScanTask;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * @author lizx
 * @date 2020/08/06
 **/
@Getter
@Setter
@ToString(callSuper=true)
public class ScanTaskRequest extends BaseScanTask {
    /**
     * 应用id
     */
    private Long appId;

}
