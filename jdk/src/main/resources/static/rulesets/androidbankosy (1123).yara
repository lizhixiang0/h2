/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: boni11
    Rule name: Android.Bankosy
    Rule id: 1123
    Created at: 2016-01-14 09:47:26
    Updated at: 2016-01-14 09:49:18
    
    Rating: #7
    Total detections: 562
*/

import "androguard"

rule Android_Bankosy
{
	meta:
		description = "This rule detects Android.Bankosy"
		sample = "ac256d630594fd4335a8351b6a476af86abef72c0342df4f47f4ae0f382543ba"
		source = "http://www.symantec.com/connect/blogs/androidbankosy-all-ears-voice-call-based-2fa"

	strings:
		$string_1 = "*21*"
		$string_2 = "#disable_forward_calls"
		$string_3 = "#lock"
		$string_4 = "#intercept_sms_start"
		
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) 
		
}
