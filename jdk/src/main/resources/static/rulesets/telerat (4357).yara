/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: roach
    Rule name: TeleRAT
    Rule id: 4357
    Created at: 2018-04-19 09:00:10
    Updated at: 2018-04-19 09:21:33
    
    Rating: #2
    Total detections: 41
*/

import "androguard"

rule TeleRAT
{
	meta:
		author = "R"
		description = "https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/"
		
	condition:
		androguard.activity(/getlastsms/i) and
		(androguard.service(/botrat/i) or androguard.service(/teleser/i))
}
