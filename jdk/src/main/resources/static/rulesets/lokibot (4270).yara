/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: LokiBot
    Rule id: 4270
    Created at: 2018-03-14 13:07:53
    Updated at: 2018-03-14 13:07:57
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule lokibot_old
{
    strings:
		$a1 = "Seller" 
		$a2 = "Domian1" 
		
	condition:
        androguard.package_name(/compse.refact.st.upsssss/) and 
		1 of ($a*)
}
