/**
 * 
 */
package com.zx.arch.service;


import com.zx.arch.dao.ZfbAppConfigMapper;
import com.zx.arch.entity.ZfbAppConfig;
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