/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 5h1vang
    Rule name: Fake Google Playstore
    Rule id: 1132
    Created at: 2016-01-18 08:58:58
    Updated at: 2016-09-29 07:36:55
    
    Rating: #0
    Total detections: 169
*/

import "androguard"

rule fake_playstore
{
	meta: 
		description = "Yara detection for Fake Google Playstore"
		samples = "1c19aedabe7628594c40a239369dc891d6b75ba4562425267ea786a8a3dcdf98"		author = "https://twitter.com/5h1vang"
		
	strings:
		$str_1 = "contact4SMS" nocase
		$str_2 = "contacts2up" nocase
		$str_3 = "com.google.game.store.close"
		$str_4 = "/webmaster/action/"

	condition:
		androguard.certificate.sha1("DC517E3302B426FA57EDD9B438C02F094D17976B") or 
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and 
		all of ($str_*)

}
