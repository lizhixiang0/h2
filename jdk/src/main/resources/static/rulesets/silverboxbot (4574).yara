/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: devploit
    Rule name: SilverBox:Bot
    Rule id: 4574
    Created at: 2018-06-22 10:41:24
    Updated at: 2018-06-22 12:56:16
    
    Rating: #0
    Total detections: 2
*/

import "androguard"


rule SilverBox:Bot
{
	meta:
		description = "This rule detects SilverBox bot Malware"
		sample = "0a5684422fc2ee1bc25882f3d07fef2627948797187c4b4e7554618af2617ac9"

	condition:
		androguard.package_name("com.dyoukbvo.chtdfdwnst") or
		
		androguard.url("http://49.51.137.120:7878") and
		
		androguard.permission("android.permission.CHANGE_NETWORK_STATE") and
		androguard.permission("android.permission.DISABLE_KEYGUARD") and
		androguard.permission("android.permission.INTERNET") and
		androguard.permission("android.permission.SEND_SMS") and
		androguard.permission("android.permission.WRITE_SMS") and
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and
		androguard.permission("android.permission.GET_TASKS") and
		androguard.permission("android.permission.READ_CALL_LOG") and
		androguard.permission("android.permission.BROADCAST_PACKAGE_REMOVED") and
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and
		androguard.permission("android.permission.CALL_PHONE") and
		androguard.permission("android.permission.READ_PHONE_STATE") and
		androguard.permission("android.permission.READ_SMS") and
		androguard.permission("android.permission.VIBRATE") and
		androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and
		androguard.permission("android.permission.WAKE_LOCK") and
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and
		androguard.permission("android.permission.RECEIVE_MMS") and
		androguard.permission("android.permission.PACKAGE_USAGE_STATS") and
		androguard.permission("android.permission.CHANGE_WIFI_STATE") and
		androguard.permission("android.permission.RECEIVE_SMS") and
		androguard.permission("android.permission.READ_CONTACTS")
}
