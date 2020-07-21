/**
 * 
 */
package com.example.h2.service;


import com.example.h2.bean.ZfbAppConfig;
import com.example.h2.dao.ZfbAppConfigMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class ZfbAppConfigServiceImpl implements ZfbAppConfigService {



    @Autowired
    private ZfbAppConfigMapper zfbAppConfigMapper;


    @Override
    public int insert(ZfbAppConfig zfbAppConfig) {
        return zfbAppConfigMapper.insert(zfbAppConfig);

    }

    @Override
    public ZfbAppConfig getAppConfigByAppCofigId(Long appConfigId) {
        return zfbAppConfigMapper.selectConfigByAppId(appConfigId);
    }
}