/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaGMBanker
    Rule id: 3938
    Created at: 2018-01-03 10:21:21
    Updated at: 2018-01-03 10:21:56
    
    Rating: #0
    Total detections: 38
*/

import "androguard"

rule YaYaGMBanker {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "29 Dec 2017"
		url = "https://koodous.com/apks?search=Bd8502a1f9934d0c1f7bb44f0b4fd7f7765798225bd2192f3fff76f5cb55259a%20OR%209425fca578661392f3b12e1f1d83b8307bfb94340ae797c2f121d365852a775e%20OR%20960422d069c5bcf14b2acbefac99b4c57b857e2a2da199c69e4526e0defc14d7%20OR%20306ca47fdf2db0010332d58f2f099d702046aa1739157163ee75177e1b9d5455"

	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.filter("com.slempo.service.activities.HTMLStart")
}
