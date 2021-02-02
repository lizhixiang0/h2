/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYAXinyinhe
    Rule id: 3940
    Created at: 2018-01-03 10:37:13
    Updated at: 2018-10-12 22:17:58
    
    Rating: #0
    Total detections: 41059
*/

import "androguard"

rule YaYAXinyinhe {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "29 Dec 2017"
		url = "https://koodous.com/apks?search=12b8da40ec9e53a83a7c4b1d490db397730123efa5e8ed39ee596d3bae42f80d%20OR%208b5b898c7ad2fc6b516800f411b7181877a89124a94ba8a9fa0e974972c67553%20OR%20d65696c077b480bb0afab2390f1efd37d701ca2f6cbaa91977d4ac76957438c7%20OR%203a5bbe5454124ba5fbaa0dc7786fd2361dd903f84ccf65be65b0b0b77d432e6e%20OR%20b05013bbabf0a24a2c8b9c7b3f3ad79b065c6daaaec51c2e61790b05932dbb58%20OR%20396324dc3f34785aca1ece255a6f142f52e831b22bf96906c2a10b61b1da4713%20OR%2098bdad683b0ae189ed0fa56fb1e147c93e96e085dff90565ee246a4f6c4e2850%20OR%20f46c21a2976af7ba23e0af54943eacdaad2fd0b3108fde6d1502879fe9c83d07%20OR%20b3c3d131200369d1c28285010b99d591f9a9c0629b0ba9fedd1b4ffe0170cf4c%20OR%200a63ca301d97930eb8352c0772fb39015e4b89cd82e72391213ee82414e60cf8"

	condition:

		androguard.filter("android.intent.action.BOOT_COMPLETED") and
		androguard.filter("android.intent.action.USER_PRESENT") and
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and

		androguard.permission("android.permission.ACCESS_MTK_MMHW") and
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and
		androguard.permission("android.permission.CAMERA") and
		androguard.permission("android.permission.INTERNET") and
		androguard.permission("android.permission.READ_PHONE_STATE") and
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and
		androguard.permission("android.permission.WAKE_LOCK")
}
