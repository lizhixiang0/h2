/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 5h1vang
    Rule name: Android.BankOsy-sh
    Rule id: 1117
    Created at: 2016-01-13 11:36:37
    Updated at: 2016-09-29 07:36:42
    
    Rating: #2
    Total detections: 557
*/

import "androguard"

rule androidbankosy_sh
{
	meta: 
		description = "Yara detection for Android.BankOsy"
		samples = "e6c1621158d37d10899018db253bf7e51113d47d5188fc363c6b5c51a606be2f and ac256d630594fd4335a8351b6a476af86abef72c0342df4f47f4ae0f382543ba"
		source = "http://www.symantec.com/connect/blogs/androidbankosy-all-ears-voice-call-based-2fa"
		author = "https://twitter.com/5h1vang"
		
	strings:
		$str_1 = "credit_cards"
		$str_2 = "yyy888222kkk"
		$str_3 = "BLOCKED_NUMBERS"
		$str_4 = "*21*"

	condition:
		androguard.certificate.sha1("CE84D46572CF77DC2BBA7C0FCCDE411D6056027B") or 
		androguard.certificate.sha1("CA048A9BB7FE1CD4F2B6C3E1C3C622D540989E36") or 
		$str_1 and $str_2 and $str_3 and $str_4
}
