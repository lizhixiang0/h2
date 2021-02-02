/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: spynote
    Rule id: 3417
    Created at: 2017-08-18 14:40:17
    Updated at: 2017-08-18 14:40:53
    
    Rating: #0
    Total detections: 181
*/

import "androguard"
import "file"
import "cuckoo"


rule Spynote
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$b_1 = "screamHacker"
			
	condition:
		any of ($b_*)
		
				
}
