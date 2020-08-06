package com.zx.arch.dao;


import com.zx.arch.entity.ZfbAppConfig;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ZfbAppConfigMapper {


	int insert(ZfbAppConfig zfbAppConfig);

	ZfbAppConfig selectConfigByAppId(Long appId);

}