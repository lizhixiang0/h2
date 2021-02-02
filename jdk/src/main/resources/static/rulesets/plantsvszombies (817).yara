/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: PlantsVsZombies
    Rule id: 817
    Created at: 2015-09-10 17:29:01
    Updated at: 2015-11-05 09:59:15
    
    Rating: #0
    Total detections: 14663
*/

import "androguard"
import "file"
import "cuckoo"


rule plantsvszombies:SMSFraud
{
	meta:
		sample = "ebc32e29ceb1aba957e2ad09a190de152b8b6e0f9a3ecb7394b3119c81deb4f3"

	
	condition:
		androguard.certificate.sha1("2846AFB58C14754206E357994801C41A19B27759")
		
		
}
