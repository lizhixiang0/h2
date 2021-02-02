/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xo
    Rule name: Adware_ 会计从业资格考试历年真题
    Rule id: 1920
    Created at: 2016-10-19 13:25:14
    Updated at: 2016-10-19 14:44:35
    
    Rating: #0
    Total detections: 409277
*/

rule Adware : test
{
	meta:
		description = "Adware Detect"
		sample = "631a898d184e5720edd5f36e6911a5416aa5b4dbbbea78838df302cffb7d36a1"
		author = "xophidia"
	strings:
	
		$string_1 = "21-11734"
		$string_2 = "()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
		$string_3 = "()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
		$string_4 = "www.meitu.com"
		$string_5 = "cookiemanager-"

	condition:
		3 of ($*)
}
