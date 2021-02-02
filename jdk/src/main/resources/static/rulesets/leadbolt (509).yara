/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: LeadBolt
    Rule id: 509
    Created at: 2015-05-23 12:10:18
    Updated at: 2015-08-06 16:00:36
    
    Rating: #2
    Total detections: 83472
*/

import "androguard"

rule leadbolt : advertising
{
	meta:
		description = "Leadbolt"
		
	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
}
