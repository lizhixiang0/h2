/**
 * 
 */
package com.example.h2.service;


import com.example.h2.bean.ZfbAppConfig;

public interface ZfbAppConfigService {

		int insert(ZfbAppConfig zfbAppConfig);

	     ZfbAppConfig getAppConfigByAppCofigId(Long appConfigId);


}