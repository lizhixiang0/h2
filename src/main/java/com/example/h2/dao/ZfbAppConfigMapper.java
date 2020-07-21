package com.example.h2.dao;


import com.example.h2.bean.ZfbAppConfig;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ZfbAppConfigMapper {


	int insert(ZfbAppConfig zfbAppConfig);

	ZfbAppConfig selectConfigByAppId(Long appId);

}