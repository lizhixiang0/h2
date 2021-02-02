/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Chinese player
    Rule id: 786
    Created at: 2015-08-19 13:44:14
    Updated at: 2015-08-19 13:46:28
    
    Rating: #0
    Total detections: 5987
*/

import "androguard"

rule chineseporn: player
{
	meta:
		sample = "4a29091b7e342958d9df00c8a37d58dfab2edbc06b05e07dcc105750f0a46c0f"

	condition:
		androguard.package_name("com.mbsp.player") and
		androguard.certificate.issuer(/O=localhost/)
		
}
