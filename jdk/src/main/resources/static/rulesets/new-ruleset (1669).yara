/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jwtgoogle
    Rule name: New Ruleset
    Rule id: 1669
    Created at: 2016-07-24 04:15:58
    Updated at: 2016-11-03 12:58:32
    
    Rating: #0
    Total detections: 3
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the cib bank apk application"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
		androguard.package_name(/com.cib.bankcib/)
		
}
