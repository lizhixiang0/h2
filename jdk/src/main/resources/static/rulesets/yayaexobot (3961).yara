/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaExobot
    Rule id: 3961
    Created at: 2018-01-05 12:00:44
    Updated at: 2018-01-05 12:00:57
    
    Rating: #0
    Total detections: 6596
*/

import "androguard"
import "cuckoo"

rule YaYaExobot: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "05 Jan 2018"
		url = "https://koodous.com/apks?search=1cd3095b176520e4bf7d3fa86ec91e852ee93b2172c8bd3113f91e2569a7c481%20OR%20%20ca2cc26e81196a2031a5cdeda91a6624ba9d34e03e5b1448dd682b0215134d15%20OR%20%2077e26712490e8ec681881b584c5e381af0dcece21f0dcfa483661f125a399a2d%20OR%20%208e9bdb1f5a37471f3f50cc9d482ea63c377e84b73d9bae6d4f37ffe403b9924e%20OR%20%20ca859564cfbfca3c99ab38c9cb30ad33ec9049fe67734bae9d9b69cd68845188%20OR%20%2059ada6b530bd2c7c15d8c552c7ebf3afcc14976bfa789a6e2c2fca3e354baab0%20OR%20%20c1ef19c9abc479070d7841846ff6b4c973b34b2035428b50999ebe63eb0547db%20OR%20%20da68cc23a89c2b794827e9f846ed5d1e371a1c14229696bc46a4d9ec380425d4%20OR%20%20498304e3f60abe29bb06661b21e579d5a25f104eb96ebf0d5d573ce9f8308b89%20OR%20%20690310a635b5c82c28a76332b83a7b34b8604e822ed8f8e4eb1f0be85c177c62%20OR%20%20ae4ed005f891101b297689530e9d07068e0a0779c7a03abe36f30b991b065ff9%20OR%20%20c28b6346d59a828ce319e94d08c35b530ae39fd5801d17e6f84a02a592621e2d%20OR%20%201cd3095b176520e4bf7d3fa86ec91e852ee93b2172c8bd3113f91e2569a7c481%20OR%20%20b8b424866ba77728034e231f295399f523154accf587424c9d42cbb1c8edba9e%20OR%20%2092c560d55ac0943022be38404fee8fd70da53cca33d7e340ea98712af389f780%20OR%20%20856d1f7cf037e031dda4accc3454d84115bc91be488b74817580e541be6abbad%20OR%20%202d1d9cabf564bc9c3a37c21cd98c7c045453dc583fab4479fe12d8e4e70f339a%20OR%20%20f6851790dc811b3a9acc425730ffeaab49c5cde4cb0a39cfcc659c4d29c908ad%20OR%20%2010931ae2c165d4786fdd9585c419a6b1d2dd07d96242d26d23daab14d684f4e0"

	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.RECEIVE_SMS") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.USES_POLICY_FORCE_LOCK")
}
