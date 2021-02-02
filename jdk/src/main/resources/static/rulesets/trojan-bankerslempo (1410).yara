/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan-Banker.Slempo
    Rule id: 1410
    Created at: 2016-05-20 07:27:25
    Updated at: 2016-10-25 11:41:21
    
    Rating: #0
    Total detections: 262
*/

rule Trojan_Banker_Slempo
{
	meta:
		description = "Trojan-Banker.Slempo"
		sample = "349baca0a31753fd8ad4122100410ee9"
		
	strings:
		$a = "org/slempo/service" nocase
		$b = /com.slempo.service/ nocase
		$c = "com/slempo/baseapp/Service" nocase
		$d = "org/slempo/baseapp/Service" nocase

	condition:
		1 of them
		
}
