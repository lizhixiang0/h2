/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mwhunter
    Rule name: Marcher targeting German Banks
    Rule id: 2356
    Created at: 2017-03-23 10:09:51
    Updated at: 2017-04-26 07:48:26
    
    Rating: #1
    Total detections: 71
*/

import "androguard"


rule Marcher : Targeting German Banks
{
	meta:
        description = "Trojan 'Marcher' targeting German Banks"
	
	strings:
		$target1 = ".starfinanz." nocase
		$target2 = ".fiducia." nocase
		$target3 = ".dkb." nocase
		$target4 = ".postbank." nocase
		$target5 = ".dkbpushtan" nocase
		
		$configC2 = "%API_URL%%PARAM%" nocase

	condition:
		1 of ($target*) 
		and $configC2 
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}
