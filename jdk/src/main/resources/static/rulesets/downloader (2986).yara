/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Downloader
    Rule id: 2986
    Created at: 2017-06-14 09:22:10
    Updated at: 2017-06-14 09:22:25
    
    Rating: #0
    Total detections: 1186
*/

import "androguard"

rule Downloader {
	condition:
		androguard.package_name("com.mopub") and
		androguard.filter("android.intent.action.ACTION_SHUTDOWN") and
		androguard.filter("android.net.wifi.supplicant.CONNECTION_CHANGE") and
		androguard.filter("android.intent.action.QUICKBOOT_POWEROFF") and
		androguard.filter("android.net.wifi.STATE_CHANGE") and
		androguard.filter("android.intent.action.BOOT_COMPLETED") and
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and
		androguard.filter("android.net.wifi.WIFI_STATE_CHANGED") and
		androguard.filter("android.intent.action.REBOOT")
}
