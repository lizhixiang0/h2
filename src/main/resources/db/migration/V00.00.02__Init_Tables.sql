


CREATE TABLE `zfb_app_config` (
  `zfb_app_config_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '建议配置表id',
  `zfb_app_name` varchar(20) NOT NULL DEFAULT '' COMMENT 'app名称',
  `zfb_position_show` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '是否显示位置',
  `zfb_position_required` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '是否位置必填 1必填 2不必填',
  `zfb_photo_show` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '是否显示图片',
  `zfb_photo_required` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '是否图片必填 1必填 2不必填',
  `zfb_app_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT 'appId',
  `zfb_app_key` varchar(64) NOT NULL DEFAULT '' COMMENT 'appkey',
  `zfb_cs_user_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '客服id',
  `zfb_cs_feed_id` varchar(25) NOT NULL DEFAULT '' COMMENT '客服名片id',
  `zfb_create_time` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '创建时间',
  `zfb_upate_time` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '更新时间',
  `zfb_cs_employee_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '员工id',
  `zfb_cs_employee_name` varchar(25) NOT NULL DEFAULT '' COMMENT '员工名称',
  PRIMARY KEY (`zfb_app_config_id`),
  UNIQUE KEY `zfb_app_id` (`zfb_app_id`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8;



CREATE TABLE `zfb_app_config_tag` (
  `zfb_app_config_tag_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '建议标签表id',
  `zfb_app_config_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '建议配置表id',
  `zfb_app_config_tag_content` varchar(100) NOT NULL DEFAULT '' COMMENT '建议标签内容',
  `zfb_rank` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '建议标签的配置位置',
  PRIMARY KEY (`zfb_app_config_tag_id`)
) ENGINE=InnoDB AUTO_INCREMENT=132 DEFAULT CHARSET=utf8 ;



CREATE TABLE `zfb_suggestion` (
  `zfb_suggestion_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '用户建议id',
  `zfb_user_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '用户id',
  `zfb_feed_id` varchar(25) NOT NULL DEFAULT '' COMMENT '用户名片id',
  `zfb_position` varchar(50) NOT NULL DEFAULT '' COMMENT '位置坐标',
  `zfb_address` varchar(50) NOT NULL DEFAULT '' COMMENT '详细位置',
  `zfb_mobile` varchar(20) NOT NULL DEFAULT '' COMMENT '用户手机号码',
  `zfb_process_state` tinyint(3) unsigned NOT NULL DEFAULT '0' COMMENT '处理状态   1未处理 2已处理 ',
  `zfb_create_time` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '创建时间',
  `zfb_update_time` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '处理时间',
  `zfb_app_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `zfb_app_name` varchar(20) NOT NULL DEFAULT '' COMMENT 'app名字',
  PRIMARY KEY (`zfb_suggestion_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1282627 DEFAULT CHARSET=utf8 ;



CREATE TABLE `zfb_suggestion_feedback` (
  `zfb_suggestion_feedback_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '客服反馈表id',
  `zfb_suggestion_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '用户建议id',
  `zfb_cs_user_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '客服id',
  `zfb_cs_feed_id` varchar(25) NOT NULL DEFAULT '' COMMENT '客服名片id',
  `zfb_cs_org_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '组织id',
  `zfb_suggestion_feedback_message` varchar(100) NOT NULL DEFAULT '' COMMENT '反馈信息',
  `zfb_app_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `zfb_create_time` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '创建时间',
  `zfb_cs_employee_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '员工id',
  `zfb_cs_employee_name` varchar(25) NOT NULL DEFAULT '' COMMENT '员工名称',
  PRIMARY KEY (`zfb_suggestion_feedback_id`),
  KEY `zfb_feedback_suggestion_id_index` (`zfb_suggestion_id`)
) ENGINE=InnoDB AUTO_INCREMENT=48 DEFAULT CHARSET=utf8;



CREATE TABLE `zfb_suggestion_img` (
  `zfb_suggestion_img_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '图片id',
  `zfb_suggestion_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '用户建议id',
  `zfb_suggestion_img_url` varchar(200) NOT NULL DEFAULT '' COMMENT '图片内容',
  `zfb_suggestion_img_width` int(10) unsigned NOT NULL COMMENT '图片宽度',
  `zfb_suggestion_img_height` int(10) unsigned NOT NULL COMMENT '图片长度',
  PRIMARY KEY (`zfb_suggestion_img_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ;



CREATE TABLE `zfb_suggestion_tag` (
  `zfb_suggestion_tag_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '用户建议-建议关联表id',
  `zfb_app_config_tag_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '建议标签表id',
  `zfb_suggestion_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '用户建议id',
  `zfb_suggestion_content` varchar(200) NOT NULL DEFAULT '""' COMMENT '用户建议',
  PRIMARY KEY (`zfb_suggestion_tag_id`),
  KEY `zfb_tag_suggestion_id_index` (`zfb_suggestion_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3931129 DEFAULT CHARSET=utf8 ;

