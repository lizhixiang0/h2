/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaLokibot
    Rule id: 3953
    Created at: 2018-01-04 16:29:36
    Updated at: 2018-01-04 16:30:54
    
    Rating: #-1
    Total detections: 47
*/

import "androguard"
import "cuckoo"


rule YaYaLokibot: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "04 Jan 2018"
		url = "https://koodous.com/apks?search=be02cf271d343ae1665588270f59a8df3700775f98edc42b3e3aecddf49f649d%20OR%20%201979d60ba17434d7b4b5403c7fd005d303831b1a584ea2bed89cfec0b45bd5c2%20OR%20%20a10f40c71721668c5050a5bf86b41a1d834a594e6e5dd82c39e1d70f12aadf8b%20OR%20%205c1857830053e64082d065998ff741b607186dc3414aa7e8d747614faae3f650%20OR%20%20cd44705b685dce0a6033760dec477921826cd05920884c3d8eb4762eaab900d1%20OR%20%20bae9151dea172acceb9dfc27298eec77dc3084d510b09f5cda3370422d02e851%20OR%20%20418bdfa331cba37b1185645c71ee2cf31eb01cfcc949569f1addbff79f73be66%20OR%20%20a9899519a45f4c5dc5029d39317d0e583cd04eb7d7fa88723b46e14227809c26%20OR%20%206fb961a96c84a5f61d17666544a259902846facb8d3e25736d93a12ee5c3087c%20OR%20%20c9f56caaa69c798c8d8d6a3beb0c23ec5c80cab2e99ef35f2a77c3b7007922df%20OR%20%2039b7ff62ec97ceb01e9a50fa15ce0ace685847039ad5ee66bd9736efc7d4a932%20OR%20%2078feb8240f4f77e6ce62441a6d213ee9778d191d8c2e78575c9e806a50f2ae45%20OR%20%20a09d9d09090ea23cbfe202a159aba717c71bf2f0f1d6eed36da4de1d42f91c74%20OR%20%20f4d0773c077787371dd3bebe93b8a630610a24d8affc0b14887ce69cc9ff24e4%20OR%20%2018c19c76a2d5d3d49f954609bcad377a23583acb6e4b7f196be1d7fdc93792f8%20OR%20%20cda01f288916686174951a6fbd5fbbc42fba8d6500050c5292bafe3a1bcb2e8d%20OR%20%207dbcecaf0e187a24b367fe05baedeb455a5b827eff6abfc626b44511d8c0029e"

	condition:

		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.ACTION_BATTERY_OKAY") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.NEW_OUTGOING_CALL") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.PACKAGE_REMOVED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON") and 
		androguard.permission("android.permission.QUICKBOOT_POWERON")
		
}
