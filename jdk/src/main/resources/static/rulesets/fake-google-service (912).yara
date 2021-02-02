/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: Fake Google Service
    Rule id: 912
    Created at: 2015-10-10 19:27:29
    Updated at: 2015-10-10 19:32:07
    
    Rating: #0
    Total detections: 269
*/

import "androguard"



rule koodous : official
{
	meta:
		description = "Ads and pron. Gets to remote host(porn) http://hwmid.ugameok.hk:8803/vvd/"
	
	strings:
		$a = "http://hwmid.ugameok.hk:8803/vvd/main?key="

	condition:
		androguard.certificate.sha1("C2:E4:C2:C7:AA:E9:ED:9C:C9:4B:B0:12:BA:DB:52:26:D1:27:87:42") or $a
		
}
