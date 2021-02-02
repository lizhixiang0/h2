/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: WapCash Developer
    Rule id: 712
    Created at: 2015-07-16 11:44:59
    Updated at: 2015-08-06 15:20:54
    
    Rating: #0
    Total detections: 71096
*/

import "androguard"

rule WapCash : official
{
	meta:
		description = "This rule detects samples fom WapCash developer"
		sample = "00d0dd7077feb4fea623bed97bb54238f2cd836314a8900f40d342ccf83f7c84"

	condition:
		androguard.certificate.sha1("804B1FED90432E8BA852D85C7FD014851C97F9CE")
		
}
