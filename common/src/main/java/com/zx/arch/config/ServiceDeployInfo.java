package com.zx.arch.config;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import java.io.Serializable;

/**
 * @author admin
 */
public class ServiceDeployInfo implements Serializable {
    private static final long serialVersionUID = 4058952630475113653L;
    private boolean deployIntranet;
    private String internetUrl;
    private String intranetUrl;
    private String secretKey;

    public ServiceDeployInfo() {
    }

    public ServiceDeployInfo(boolean deployIntranet, String internetUrl, String intranetUrl, String secretKey) {
        this.deployIntranet = deployIntranet;
        this.internetUrl = internetUrl;
        this.intranetUrl = intranetUrl;
        this.secretKey = secretKey;
    }

    public boolean isDeployIntranet() {
        return this.deployIntranet;
    }

    public String getInternetUrl() {
        return this.internetUrl;
    }

    public String getIntranetUrl() {
        return this.intranetUrl;
    }

    public String getSecretKey() {
        return this.secretKey;
    }

    public void setDeployIntranet(final boolean deployIntranet) {
        this.deployIntranet = deployIntranet;
    }

    public void setInternetUrl(final String internetUrl) {
        this.internetUrl = internetUrl;
    }

    public void setIntranetUrl(final String intranetUrl) {
        this.intranetUrl = intranetUrl;
    }

    public void setSecretKey(final String secretKey) {
        this.secretKey = secretKey;
    }
}
