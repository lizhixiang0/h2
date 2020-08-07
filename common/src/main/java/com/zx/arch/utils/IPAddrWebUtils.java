package com.zx.arch.utils;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

public class IPAddrWebUtils {
    public IPAddrWebUtils() {
    }

    public static String getRealIP(HttpServletRequest request) {
        String ip = request.getHeader("X-Real-IP");
        if (StringUtils.isEmpty(ip) || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("x-forwarded-for");
            if (StringUtils.isNotEmpty(ip) && ip.contains(",")) {
                ip = ip.substring(0, ip.indexOf(","));
            }
        }

        if (StringUtils.isEmpty(ip) || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }

        if (StringUtils.isEmpty(ip) || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }

        if (StringUtils.isEmpty(ip) || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        return StringUtils.trim(ip);
    }

    public static Long getRealIPAsLong(HttpServletRequest request) {
        return ipToLong(getRealIP(request));
    }

    public static long ipToLong(String ipAddress) {
        long result = 0L;
        if (ipAddress != null) {
            String[] ipAddressInArray = ipAddress.trim().split("\\.");
            if (ipAddressInArray != null && ipAddressInArray.length == 4) {
                for(int i = 3; i >= 0; --i) {
                    long ip = Long.parseLong(ipAddressInArray[3 - i]);
                    result |= ip << i * 8;
                }
            }
        }

        return result;
    }
}
