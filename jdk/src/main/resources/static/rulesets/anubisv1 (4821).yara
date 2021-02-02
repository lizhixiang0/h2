/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: t1g3r
    Rule name: Anubisv1
    Rule id: 4821
    Created at: 2018-08-21 08:33:21
    Updated at: 2018-08-21 10:09:28
    
    Rating: #-1
    Total detections: 19
*/

import "androguard"
import "cuckoo"


rule AnubisV1: rule0 {
	meta:
		author = "AnubisV1"
		date = "21 Aug 2018"
		url = "https://koodous.com/apks?search=tag:anubis%20AND%20date:%3E2018-07-30"

	condition:
		androguard.displayed_version("1.0") and 

		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.DREAMING_STOPPED") and 
		androguard.filter("android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.PACKAGE_REMOVED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.intent.action.SCREEN_ON") and 
		androguard.filter("android.intent.action.SEND") and 
		androguard.filter("android.intent.action.SENDTO") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and 
		androguard.filter("android.net.wifi.WIFI_STATE_CHANGED") and 
		androguard.filter("android.provider.Telephony.SMS_DELIVER") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.filter("android.provider.Telephony.WAP_PUSH_DELIVER") and 
		androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON") and 

		androguard.functionality.socket.code(/invoke\-static\ v1\,\ v2\,\ v3\,\ v4\,\ v5\,\ Landroid\/view\/Gravity\;\-\>accept\(I\ I\ I\ Landroid\/graphics\/Rect\;\ Landroid\/graphics\/Rect\;\)V/) and 
		androguard.functionality.socket.code(/invoke\-static\/range\ v0\ \.\.\.\ v5\,\ Landroid\/view\/Gravity\;\-\>accept\(I\ I\ I\ Landroid\/graphics\/Rect\;\ Landroid\/graphics\/Rect\;\ I\)V/) and 

		androguard.number_of_filters == 17 and 

		androguard.number_of_receivers == 4 and 

		androguard.permission("android.permission.ACCESS_FINE_LOCATION") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.CALL_PHONE") and 
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.PACKAGE_USAGE_STATS") and 
		androguard.permission("android.permission.READ_CONTACTS") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_SMS") and 
		androguard.permission("android.permission.RECORD_AUDIO") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.WRITE_SMS")
}
