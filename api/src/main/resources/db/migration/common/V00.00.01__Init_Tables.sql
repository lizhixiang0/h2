DROP TABLE IF EXISTS `ac_user`;
CREATE TABLE `ac_user` (
                           `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '用户ID',
                           `age` int(4) DEFAULT NULL,
                           `name` varchar(32) DEFAULT NULL,
                           PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

