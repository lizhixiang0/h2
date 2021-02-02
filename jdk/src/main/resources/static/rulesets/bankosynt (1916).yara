/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xo
    Rule name: BankosyNT
    Rule id: 1916
    Created at: 2016-10-19 12:38:05
    Updated at: 2016-11-27 21:21:53
    
    Rating: #0
    Total detections: 103
*/

import "androguard"

rule Android_Bankosy_nt
{
meta:
	description = "Try Android.Bankosy"
	sample = "ac256d630594fd4335a8351b6a476af86abef72c0342df4f47f4ae0f382543ba"
	source = "http://www.symantec.com/connect/blogs/androidbankosy-all-ears-voice-call-based-2fa"

strings:
	$string_1 = "#21#"
	$string_2 = "#disable_forward_calls"
	$string_3 = "#unlock"
	$string_4 = "#intercept_sms_stop"
	
		
condition:
	all of ($string_*) and
	androguard.permission(/android.permission.SEND_SMS/) 
}
