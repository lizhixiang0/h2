package com.example.h2;

import com.zx.arch.entity.ZfbAppConfig;
import com.zx.arch.service.ZfbAppConfigServiceImpl;
import config.DomainConfigTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;


@SpringBootTest
@ContextConfiguration(classes = { DomainConfigTest.class })
public class MainTests {
	@Autowired
	ZfbAppConfigServiceImpl zfbAppConfigServiceImpl;

	@Test
	public void insertTest() {

		//TODO: Test goes here...

		ZfbAppConfig zfg = new ZfbAppConfig();
		zfg.setAppName("dfdsfds");
		zfg.setPositionShow(0);
		zfg.setPhotoShow(0);
		zfg.setAppId(1L);
		zfg.setAppKey("0");
		zfg.setCsUserId(1L);
		zfg.setCsFeedId("0001");
		zfg.setCreateTime(201700725L);
		zfg.setUpateTime(0L);
		System.out.println("");
		zfbAppConfigServiceImpl.insert(zfg);
		ZfbAppConfig result = zfbAppConfigServiceImpl.getAppConfigByAppCofigId(1L);
		System.out.println(result);
	}
}