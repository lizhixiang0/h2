/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Chinese setting
    Rule id: 787
    Created at: 2015-08-19 14:23:55
    Updated at: 2015-08-19 14:24:55
    
    Rating: #0
    Total detections: 3409
*/

import "androguard"


rule chinese_setting
{
	meta:
		sample = "ff53d69fd280a56920c02772ceb76ec6b0bd64b831e85a6c69e0a52d1a053fab"

	condition:
		androguard.package_name("com.anrd.sysservices") and
		androguard.certificate.issuer(/localhost/)
		
}
