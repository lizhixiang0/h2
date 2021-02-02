/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Cloudsota
    Rule id: 1017
    Created at: 2015-11-13 13:38:18
    Updated at: 2015-11-13 14:10:24
    
    Rating: #3
    Total detections: 74
*/

import "androguard"


rule cloudsota
{
	meta:
		description = "http://www.cmcm.com/blog/en/security/2015-11-09/842.html"
		sample = "ff10aca93c95bb9c17e0fce10d819210907fcf84cfb061cdba4bd5ce47fd11d3"

	condition:
		androguard.certificate.sha1("FD2FF510E7896EB93840B6DFE8A109850F640CA9") or
		androguard.certificate.sha1("B03DB174D2643B2A7C23D6403169345D225DDB4F") or
		androguard.certificate.sha1("C3AA1AC48D59E56189BD1F1B09BD1C3FE2A33CB0")
		
}
