/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: LLC Developer
    Rule id: 713
    Created at: 2015-07-16 12:00:10
    Updated at: 2015-08-06 15:20:55
    
    Rating: #0
    Total detections: 67513
*/

import "androguard"

rule LLCdev : official
{
	meta:
		description = "This rule detects samples fom LLC developer"
		sample = "00d0dd7077feb4fea623bed97bb54238f2cd836314a8900f40d342ccf83f7c84"

	condition:
		androguard.certificate.sha1("D7FE504792CD5F67A7AF9F26C771F990CA0CB036")
		
}
