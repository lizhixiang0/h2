package com.zx.arch.response;


import com.zx.arch.constant.VasConstants;
import com.zx.arch.constant.VasConstants.ServiceType;
import lombok.Data;

import java.io.Serializable;
import java.util.Set;

/**
 * @author admin
 */
@Data
public class PaxstoreInstanceInfo implements Serializable {
    private static final long serialVersionUID = -6637196334786656280L;
    private String envCode;
    private String apiUrl;
    private String apiSecretToPaxstore;
    private String apiSecretFromPaxstore;
    private Set<ServiceType> enabledServices;

    public PaxstoreInstanceInfo() {
    }

    public boolean isServiceEnabled(ServiceType serviceType) {
        return serviceType != null && this.enabledServices != null && this.enabledServices.contains(serviceType);
    }
}
