package com.zx.arch.response;


import com.zx.arch.constant.VasConstants;
import com.zx.arch.constant.VasConstants.ServiceType;

import java.io.Serializable;
import java.util.Set;

/**
 * @author admin
 */
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

    public String getEnvCode() {
        return this.envCode;
    }

    public String getApiUrl() {
        return this.apiUrl;
    }

    public String getApiSecretToPaxstore() {
        return this.apiSecretToPaxstore;
    }

    public String getApiSecretFromPaxstore() {
        return this.apiSecretFromPaxstore;
    }

    public Set<ServiceType> getEnabledServices() {
        return this.enabledServices;
    }

    public void setEnvCode(final String envCode) {
        this.envCode = envCode;
    }

    public void setApiUrl(final String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public void setApiSecretToPaxstore(final String apiSecretToPaxstore) {
        this.apiSecretToPaxstore = apiSecretToPaxstore;
    }

    public void setApiSecretFromPaxstore(final String apiSecretFromPaxstore) {
        this.apiSecretFromPaxstore = apiSecretFromPaxstore;
    }

    public void setEnabledServices(final Set<ServiceType> enabledServices) {
        this.enabledServices = enabledServices;
    }
}
