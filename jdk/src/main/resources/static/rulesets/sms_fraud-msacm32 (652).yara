/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: sms_fraud - MSACM32
    Rule id: 652
    Created at: 2015-07-01 12:17:26
    Updated at: 2016-01-14 16:12:06
    
    Rating: #1
    Total detections: 88742
*/

import "androguard"

rule sms_fraud : MSACM32
{
	meta:
		description = "sms-fraud examples"
		sample = "8b9cabd2dafbba57bc35a19b83bf6027d778f3b247e27262ced618e031f9ca3d c52112b45164b37feeb81e0b5c4fcbbed3cfce9a2782a2a5001fb37cfb41e993"

	strings:
		$string_a = "MSACM32.dll"
		$string_b = "android.provider.Telephony.SMS_RECEIVED"
		$string_c = "MAIN_TEXT_TAG"

	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.SEND_SMS/)
		
}


rule sms_fraud_gen : generic
{
	meta:
		description = "This is just an example"
		thread_level = 3
		in_the_wild = true

	strings:
		$a = "080229013346Z"
		$c = "350717013346Z0"
		$b = "NUMBER_CHAR_EXP_SIGN"

	condition:
		$a and $b and $c and
		androguard.permission(/android.permission.SEND_SMS/)
}
