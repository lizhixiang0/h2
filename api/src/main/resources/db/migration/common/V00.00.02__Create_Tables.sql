-- ----------------------------
-- Table structure for ac_engine
-- ----------------------------
DROP TABLE IF EXISTS `ac_engine`;
CREATE TABLE `ac_engine` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'primary key',
  `name` varchar(32) NOT NULL COMMENT '扫描引擎名字',
  `identifier` varchar(16) NOT NULL COMMENT '扫描引擎唯一标识',
  `description` varchar(255) DEFAULT NULL COMMENT '描述',
  `icon` longtext,
  `access_key` varchar(32) NOT NULL,
  `secret_key` varchar(64) NOT NULL,
  `available` bit(1) NOT NULL COMMENT '扫描引擎是否集成到appscan',
  `charge`  bit(1) NOT NULL COMMENT '是否收费',
  `support_new_task_notify`  bit(1) NOT NULL COMMENT '是否通知',
  `api_base_url`  varchar(32) NOT NULL COMMENT '引擎url',
  `created_time` bigint(32) NULL DEFAULT NULL COMMENT '创建时间',
  `created_by` int(11) NULL DEFAULT NULL COMMENT '创建者',
  `updated_time` bigint(32) NULL DEFAULT NULL COMMENT '更新时间',
  `updated_by` int(11) NULL DEFAULT NULL COMMENT '更新者',
  PRIMARY KEY (`id`)
) ;