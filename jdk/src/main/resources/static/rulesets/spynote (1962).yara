/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SpyNote
    Rule id: 1962
    Created at: 2016-11-15 09:20:28
    Updated at: 2016-11-15 09:21:12
    
    Rating: #0
    Total detections: 700
*/

import "androguard"


rule spynote: RAT
{
	meta:
		sample = "bd3269ec0d8e0fc2fbb8f01584a7f5de320a49dfb6a8cc60119ad00c7c0356a5"


	condition:
		androguard.package_name("com.spynote.software.stubspynote")
}
