/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Banker Generic1
    Rule id: 1938
    Created at: 2016-10-28 07:04:48
    Updated at: 2016-11-04 09:49:05
    
    Rating: #0
    Total detections: 4174
*/

rule Banker2 {
	strings:
		$r1 = "SmsReceiver"
		$r2 = "BootReceiver"
		$r3 = "AdminReceiver"
		$r4 = "AlarmReceiver"
		$r5 = "ServiceDestroyReceiver"
		$r6 = "AdminRightsReceiver"
		$r7 = "MessageReceiver"

		$s1 = "USSDService"
		$s2 = "GPService"
		$s3 = "FDService"
		$s4 = "MainService"
			
		$as1 = "AdminService"
		$as2 = "AdminRightsService"
		
	condition:
	3 of ($r*) and all of ($s*) and 1 of ($as*)
		
}

rule Trojan_SMS:Banker {
	strings:
		$ = "Landroid/telephony/SmsManager"
		$ = "szClassname"
		$ = "szICCONSEND"
		$ = "szModuleSmsStatus"
		$ = "szModuleSmsStatusId"
		$ = "szName"
		$ = "szNomer"
		$ = "szNum"
		$ = "szOk"
		$ = "szTel"
		$ = "szText"
		$ = "szpkgname"

	condition:
		all of them
}
