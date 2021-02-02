/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaBanker2
    Rule id: 3962
    Created at: 2018-01-05 13:57:29
    Updated at: 2018-01-05 13:57:39
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "cuckoo"


rule YaYaBanker2: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "05 Jan 2018"
		url = "https://koodous.com/apks?search=e96b38e2f76e38e5a02f41eec626330799e6b20a3ddfdaa2da62c0672fc8cbf5%20OR%20%200c5a24d64e0b6a7ad2d5b7fe928b939b6635f1129dc2239057bd381a94ce9aed%20OR%20%204680ec774eabfa22fff77eed8ee47da5ffc4b3563b29c313b51453cf161e7cc2%20OR%20%209f9412fe618c239227184189d71eab3e998db22b625a3324832734bb05b4aa0b%20OR%20%207c28b64d3e6a529cf3b3cfb308c4cba9e624271c2215575cbd0b66551fc0d9fe%20OR%20%200f6530b8120399437b256f7f5004dffc5763f2397382318ad313e16943641224%20OR%20%200852925981807512a1367fb7423956b2b2dbe617a42952de4e1af08a611f21d7%20OR%20%2012fd9f2a9150414618770353c0661d422091bdcddaae814f26401fa826da9423%20OR%20%20e44e54ddf46457eafc368c17e353e8aeb119f20f8c38060daed1d954670e1c87%20OR%20%2072c733e3fdf7ee9f74e4473f7e872a2aa6b425d249ad186c98615f9b3766f197"

	condition:
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v2\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 

		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 

		((androguard.url("/add.php") or 
		cuckoo.network.http_request(/\/add\.php/)) or 

		(androguard.url("/chins.php") or 
		cuckoo.network.http_request(/\/chins\.php/)) or 

		(androguard.url("/live.php") or 
		cuckoo.network.http_request(/\/live\.php/)))
}
