/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: baal
    Rule name: HummingBad
    Rule id: 1770
    Created at: 2016-08-29 13:30:55
    Updated at: 2016-08-29 13:36:41
    
    Rating: #0
    Total detections: 357
*/

import "androguard"



rule HummingBad : malware
{
	meta:
		description = "https://www.checkpoint.com/downloads/resources/wp-hummingbad-research-report.pdf"


	strings:
		$a = "com.android.vending.INSTALL_REFERRER"
		$b = "Superuser.apk"

	condition:
		(androguard.package_name("Com.andr0id.cmvchinme") or
		androguard.package_name("Com.swiping.whale") or
		androguard.package_name("Com.andr0id.cmvchinmf") or
		androguard.package_name("com.quick.launcher")) and
		
		$a and $b
		
		
	
}
