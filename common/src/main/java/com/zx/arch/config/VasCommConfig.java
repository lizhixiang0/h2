package com.zx.arch.config;

import com.google.common.base.Preconditions;
import com.zx.arch.constant.VasConstants.ServiceType;
import com.zx.arch.exception.GenericVasException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author admin
 */
@Configuration
@ConfigurationProperties(
        prefix = "vas-common"
)
@Import({
        PaxstoreProps.class
})
public class VasCommConfig implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(VasCommConfig.class);
    private Map<ServiceType, ServiceDeployInfo> serviceInfo;
    @Autowired
    private PaxstoreProps paxstore;
    private ServiceType currentServiceType;
    private List<String> envListSupportNotification = new ArrayList();

    public VasCommConfig() {
    }

    public String getCurrentServiceSecurityKey() {
        return this.getInternalSecurityKey(this.currentServiceType);
    }

    public String getInternalSecurityKey(ServiceType serviceType) {
        if (serviceType != null && this.serviceInfo != null) {
            return this.serviceInfo.get(serviceType) == null ? null : ((ServiceDeployInfo)this.serviceInfo.get(serviceType)).getSecretKey();
        } else {
            return null;
        }
    }

    public String getInternalSecurityKey(String serviceType) {
        if (serviceType == null) {
            return null;
        } else {
            return this.getServiceDeployInfo(serviceType) == null ? null : this.getServiceDeployInfo(serviceType).getSecretKey();
        }
    }

    private ServiceDeployInfo getServiceDeployInfo(String serviceTypeStr) {
        if (serviceTypeStr == null) {
            return null;
        } else {
            ServiceType serviceType = ServiceType.valueOfStr(serviceTypeStr);
            return serviceType == null ? null : (ServiceDeployInfo)this.serviceInfo.get(serviceType);
        }
    }

    public String getServiceApiBaseUrl(ServiceType targetService) {
        return this.isCurrentServiceInSameIntranet(targetService) ? ((ServiceDeployInfo)this.serviceInfo.get(targetService)).getIntranetUrl() : ((ServiceDeployInfo)this.serviceInfo.get(targetService)).getInternetUrl();
    }

    public String getServiceApiInternetBaseUrl(ServiceType targetService) {
        return ((ServiceDeployInfo)this.serviceInfo.get(targetService)).getInternetUrl();
    }

    public boolean isCurrentServiceInSameIntranet(ServiceType targetService) {
        ServiceDeployInfo targetServiceDeployInfo = (ServiceDeployInfo)this.serviceInfo.get(targetService);
        ServiceDeployInfo currentServiceDeployInfo = (ServiceDeployInfo)this.serviceInfo.get(this.currentServiceType);
        if (targetServiceDeployInfo == null) {
            throw new GenericVasException(19, String.format("configuration of vas-common.%s not found", targetService.getValue()));
        } else {
            return currentServiceDeployInfo != null ? currentServiceDeployInfo.isDeployIntranet() && targetServiceDeployInfo.isDeployIntranet() : false;
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Preconditions.checkNotNull(this.paxstore, "Property paxstore is null");
        this.paxstore.postInit();
        logger.info("VasCommConfig>>>");
        logger.info("currentServiceType is {}", this.currentServiceType);
    }

    public Map<ServiceType, ServiceDeployInfo> getServiceInfo() {
        return this.serviceInfo;
    }

    public PaxstoreProps getPaxstore() {
        return this.paxstore;
    }

    public ServiceType getCurrentServiceType() {
        return this.currentServiceType;
    }

    public List<String> getEnvListSupportNotification() {
        return this.envListSupportNotification;
    }

    public void setServiceInfo(final Map<ServiceType, ServiceDeployInfo> serviceInfo) {
        this.serviceInfo = serviceInfo;
    }

    public void setPaxstore(final PaxstoreProps paxstore) {
        this.paxstore = paxstore;
    }

    public void setCurrentServiceType(final ServiceType currentServiceType) {
        this.currentServiceType = currentServiceType;
    }

    public void setEnvListSupportNotification(final List<String> envListSupportNotification) {
        this.envListSupportNotification = envListSupportNotification;
    }
}
