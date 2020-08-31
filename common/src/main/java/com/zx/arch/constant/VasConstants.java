package com.zx.arch.constant;

/**
 * @author lizx
 * @date 2020/08/31
 **/
public interface VasConstants {
    String LOAD_BALANCED_REST_TEMPLATE_BEAN_NAME = "loadBalancedRestTemplate";

    public interface ServiceRegName {
        String AIRVIEWER_SERVER = "airviewer-server";
    }

    public interface VasTokenClaim {
        String ENV_CODE = "envCode";
        String SERVICE_TYPE = "serviceType";
        String USER_ID = "userId";
        String CURRENT_USER = "current-user";
    }

    public interface VasHttpHeader {
        String ACCESS_TOKEN = "accessToken";
        String AUTHORIZATION = "authorization";
        String ENV_CODE = "envCode";
        String SERVICE_TYPE = "serviceType";
    }

    public static enum ServiceType {
        VAS_PLATFORM("vas_platform"),
        INSIGHT("cloud_data"),
        CLOUD_MSG("cloud_msg"),
        AIRVIEWER("posviewer"),
        STACKLYTICS("stacklytics"),
        APP_SCAN("app_scan"),
        SMART_LANDING("smart_landing");

        private String serviceType;

        private ServiceType(String serviceType) {
            this.serviceType = serviceType;
        }

        public String getValue() {
            return this.serviceType;
        }

        public static VasConstants.ServiceType valueOfStr(String serviceTypeStr) {
            if (serviceTypeStr != null && !"".equals(serviceTypeStr.trim())) {
                VasConstants.ServiceType[] var1 = values();
                int var2 = var1.length;

                for(int var3 = 0; var3 < var2; ++var3) {
                    VasConstants.ServiceType serviceType = var1[var3];
                    if (serviceType.getValue().equals(serviceTypeStr)) {
                        return serviceType;
                    }
                }

                return null;
            } else {
                return null;
            }
        }
    }
}
