/**
 * 
 */
package com.zx.arch.service;


import com.zx.arch.entity.ZfbAppConfig;

public interface ZfbAppConfigService {

		int insert(ZfbAppConfig zfbAppConfig);

	     ZfbAppConfig getAppConfigByAppCofigId(Long appConfigId);


}