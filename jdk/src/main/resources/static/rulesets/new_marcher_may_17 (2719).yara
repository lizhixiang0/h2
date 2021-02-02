/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: New_Marcher_May_17
    Rule id: 2719
    Created at: 2017-05-18 19:52:33
    Updated at: 2017-05-23 00:11:29
    
    Rating: #0
    Total detections: 157
*/

import "androguard"
import "file"
import "cuckoo"


rule New_Marcher_May_17
{
	meta:
		description = "This rule detects new Marcher samples with jumbled Receiver and Service names"
		sample = "68ce40e9bdb43b900bf3cb1697b37e29"

	
	condition:
		androguard.service(/\.[a-z]{1}[0-9]{3}[a-z]{1}\b/) and
		androguard.receiver(/\.[a-z]{1}[0-9]{3}[a-z]{1}\b/)
		
		
		
}
