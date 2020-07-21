/*
 * *******************************************************************************
 * COPYRIGHT
 *               PAX TECHNOLOGY, Inc. PROPRIETARY INFORMATION
 *   This software is supplied under the terms of a license agreement or
 *   nondisclosure agreement with PAX  Technology, Inc. and may not be copied
 *   or disclosed except in accordance with the terms in that agreement.
 *
 *      Copyright (C) 2017 PAX Technology, Inc. All rights reserved.
 * *******************************************************************************
 */

package com.example.h2.il8n;

import com.example.h2.spring.SystemConstants;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.web.servlet.i18n.AbstractLocaleResolver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Locale;

/**
 * The type Pax api locale resolver.
 */
public class AppScanApiLocaleResolver extends AbstractLocaleResolver {

    @Override
    public Locale resolveLocale(HttpServletRequest request) {
        String localeStr = request.getHeader(HttpHeaders.CONTENT_LANGUAGE);

        if (StringUtils.startsWith(localeStr, "zh")) {
            localeStr = Locale.SIMPLIFIED_CHINESE.toString();
        }

        if (StringUtils.isNotBlank(localeStr) && isLocaleAvailable(localeStr)) {
            if (localeStr.contains(String.valueOf('_'))) {
                final String[] localeArr = localeStr.split(String.valueOf('_'));
                return new Locale(localeArr[0], localeArr[1]);
            }
            return new Locale(localeStr, "");
        } else {
            return new Locale(SystemConstants.DEFAULT_LOCALE);
        }
    }

    @Override
    public void setLocale(HttpServletRequest request, HttpServletResponse response, Locale locale) {
        throw new UnsupportedOperationException("setLocale() is not supported in PaxApiLocaleResolver");
    }

    private boolean isLocaleAvailable(String localeStr) {
        for (String availableLocale : SystemConstants.SUPPORT_LOCALES) {
            if (StringUtils.equals(availableLocale, localeStr)) {
                return true;
            }
        }

        return true;
    }
}
