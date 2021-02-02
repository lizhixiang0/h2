/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Banker Generic
    Rule id: 1901
    Created at: 2016-10-11 07:36:18
    Updated at: 2017-04-18 11:28:33
    
    Rating: #0
    Total detections: 331
*/

import "androguard"

rule Banker1 {
	strings:
		$ = "MessageReceiver"
		$ = "AlarmReceiver"
		$ = "BootReceiver"
		$ = "AdminRightsReceiver"
		$ = "AdminService"
		$ = "FDService"
		$ = "USSDService"
		$ = "MainService"

	condition:
		all of them
		
}

rule Banker2 {
	strings:
		$ = "85.93.5.228/index.php?action=command"
		$ = "email@fgdf.er"
		$ = "majskdd@ffsa.com"
		$ = "185.48.56.10"
	condition:
		1 of them
}



rule Zitmo
{
	meta:
		description = "Trojan-Banker.AndroidOS.Zitmo"
		sample = "c0dde72ea2a2db61ae56654c7c9a570a8052182ec6cc9697f3415a012b8e7c1f"

	condition:
		androguard.receiver("com.security.service.receiver.SmsReceiver") and
		androguard.receiver("com.security.service.receiver.RebootReceiver") and
		androguard.receiver("com.security.service.receiver.ActionReceiver")
		
}

rule Banker3
{
	strings:
	$ = "cosmetiq/fl/service" nocase
	
	condition:
	1 of them
	
}
