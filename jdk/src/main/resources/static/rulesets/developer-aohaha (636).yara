/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Developer AoHaHa
    Rule id: 636
    Created at: 2015-06-26 11:05:33
    Updated at: 2015-08-06 15:20:37
    
    Rating: #0
    Total detections: 36882
*/

import "androguard"


rule AoHaHa: SMSSender
{
	condition:
		androguard.certificate.sha1("79A25BCBF6FC9A452292105F0B72207C3381F288")
}
