/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Adware ASDD
    Rule id: 640
    Created at: 2015-06-26 19:55:12
    Updated at: 2015-08-06 15:20:38
    
    Rating: #0
    Total detections: 43976
*/

import "androguard"


rule adware:asd
{
	condition:
		
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")
		
}
