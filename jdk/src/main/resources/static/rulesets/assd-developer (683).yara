/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: ASSD developer
    Rule id: 683
    Created at: 2015-07-13 08:53:23
    Updated at: 2015-08-06 15:20:53
    
    Rating: #0
    Total detections: 32873
*/

import "androguard"

rule koodous : official
{
	meta:
		description = "This rule detects apks fom ASSD developer"
		sample = "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e"

	condition:
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")
		
}
