/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: vsoft
    Rule name: New Ruleset
    Rule id: 1257
    Created at: 2016-03-08 21:26:47
    Updated at: 2016-03-08 21:27:02
    
    Rating: #0
    Total detections: 46980
*/

import "androguard"

rule leadbolt : advertising
{
	meta:
		description = "Leadbolt"
		
	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
}
