/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaRuleEXOBOT
    Rule id: 4022
    Created at: 2018-01-19 09:45:20
    Updated at: 2018-01-19 15:54:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "cuckoo"


rule YaYaRuleEXOBOT: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "19 Jan 2018"
		description = "https://clientsidedetection.com/exobot_android_malware_spreading_via_google_play_store.html"

	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLE_REQUESTED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 

		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.run_binary.code(/invoke\-static\ Ljava\/lang\/Runtime\;\-\>getRuntime\(\)Ljava\/lang\/Runtime\;/) and 
		androguard.functionality.run_binary.code(/invoke\-virtual\ v1\,\ v2\,\ Ljava\/lang\/Runtime\;\-\>exec\(Ljava\/lang\/String\;\)Ljava\/lang\/Process\;/) and 
		androguard.functionality.run_binary.method(/a/) and 
		androguard.functionality.ssl.method(/\<clinit\>/) and 

		androguard.number_of_filters == 7 and 

		androguard.number_of_receivers == 2 and 

		androguard.number_of_services == 2 and 

		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE")
}
