/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: omeh2003
    Rule name: New Ruleset
    Rule id: 5873
    Created at: 2019-08-27 01:21:17
    Updated at: 2019-08-27 01:23:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule WhatsApp  : Virus
{


	condition:
	   androguard.url("google.com/iidKZ.KxZ/=-Z[")
	   
	   
	   

		
}
