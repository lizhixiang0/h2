/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: feckeny
    Rule id: 486
    Created at: 2015-05-12 11:49:02
    Updated at: 2015-08-06 15:20:05
    
    Rating: #0
    Total detections: 447
*/

import "androguard"


rule feckeny
{
	meta:
		description = "This ruleset looks for feckeny's apps"

	condition:
		androguard.certificate.issuer(/feckeny/) 
		or androguard.certificate.subject(/feckeny/)
}
