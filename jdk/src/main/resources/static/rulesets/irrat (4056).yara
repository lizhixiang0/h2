/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: roach
    Rule name: IRRat
    Rule id: 4056
    Created at: 2018-01-29 11:10:59
    Updated at: 2018-04-19 09:21:20
    
    Rating: #0
    Total detections: 47
*/

import "androguard"

rule IRRat 
{
	meta:
		author = "R"
		description = "https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/"

	condition:
		androguard.service(/botcontril/i) and
		androguard.url(/api.telegram.org\/bot/)
}
