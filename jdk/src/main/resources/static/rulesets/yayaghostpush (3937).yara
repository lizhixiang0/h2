/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaGhostPush
    Rule id: 3937
    Created at: 2018-01-03 10:08:40
    Updated at: 2018-01-03 10:12:19
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule YaYaGhostPush {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "29 Dec 2017"
		url = "https://koodous.com/apks?search=0f9e0b86fd3685ee0960ad6dfdc9e2e03c81ce203888546d3cc7740c0a07e5aa%20OR%20%205fbcab01cf7b231d3cc0b26b86e58c95a82cebaa34e451b7b4d3f5e78dad3ea5%20OR%20%2003eda7f7ecaa6425d264d82fb22e7b7218dfdd17bf9d5bbdd70045fecb3eb0e5"

	condition:
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.CAMERA") and 
		androguard.permission("android.permission.GET_ACCOUNTS") and 
		androguard.permission("android.permission.KILL_BACKGROUND_PROCESSES") and 
		androguard.permission("android.permission.READ_SETTINGS") and 
		androguard.permission("android.permission.RECEIVE_USER_PRESENT") and 
		androguard.permission("android.permission.WRITE_SETTINGS") and 

		androguard.service("com.android.wp.net.log.UpService") and 
		androguard.service("com.android.wp.net.log.service.ActivateService")
}
