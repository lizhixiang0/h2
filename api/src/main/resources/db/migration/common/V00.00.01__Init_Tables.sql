DROP TABLE IF EXISTS `ac_apk_file`;
CREATE TABLE `ac_apk_file` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'primary key',
  `size` int(11)  COMMENT 'apk文件大小',
  `md5` varchar(32)  COMMENT 'apk文件md5码',
  `download_url` varchar(255) NOT NULL COMMENT '文件下载地址',
  `status` char(1) NOT NULL COMMENT '状态',
  `file_id` varchar(255)  COMMENT '文件服务器id',
  `created_time` bigint(32) NULL DEFAULT NULL COMMENT '创建时间',
  `created_by` int(11) NULL DEFAULT NULL COMMENT '创建者',
  `updated_time` bigint(32) NULL DEFAULT NULL COMMENT '更新时间',
  `updated_by` int(11) NULL DEFAULT NULL COMMENT '更新者',
  PRIMARY KEY (`id`)
);