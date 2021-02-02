/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: baal
    Rule name: Godless
    Rule id: 1532
    Created at: 2016-06-23 15:31:06
    Updated at: 2016-09-22 14:09:43
    
    Rating: #0
    Total detections: 74
*/

rule Godless_malware
{
	meta:
		description = "GODLESS Mobile Malware"

	strings:
		$a = "android.intent.action.SCREEN_OFF"
		$b = "system/app/AndroidDaemonFrame.apk"
		$c = "libgodlikelib.so"
		

	condition:

		$a and $b and $c
		
}
