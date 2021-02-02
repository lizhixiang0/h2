/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Malicious_Apps_with_VirusService
    Rule id: 2026
    Created at: 2016-12-07 22:58:17
    Updated at: 2017-01-17 18:26:38
    
    Rating: #0
    Total detections: 214
*/

import "androguard"
import "file"
import "cuckoo"


rule test2
{
	meta:
		description = "This rule detects apps with VirusService"
		sample = "5C0A65D3AE9F45C9829FDF216C6E7A75AD33627A"
	
	condition:
		androguard.service(/\.VirusService/i)
			

		
}
