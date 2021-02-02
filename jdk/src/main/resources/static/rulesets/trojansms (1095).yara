/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: TrojanSMS
    Rule id: 1095
    Created at: 2016-01-04 09:48:46
    Updated at: 2016-01-04 09:50:59
    
    Rating: #4
    Total detections: 76
*/

rule trojanSMS
{
	meta:
		description = "This rule detects trojan SMS"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"

	strings:
		$a = "sendMultipartTextMessage"
		$b = "l68g66qypPs="
		$c = "MY7WPp+JQGc="
		$d = "com.android.install"
		
	condition:
		all of them
		
}
