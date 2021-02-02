/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: DroidJack infested apps
    Rule id: 2123
    Created at: 2017-01-11 00:31:17
    Updated at: 2017-01-11 17:40:55
    
    Rating: #0
    Total detections: 4823
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects malicious apps with DroidJack components"
		sample = "51b1872a8e2257c660e4f5b46412cb38"

	condition:
		androguard.package_name("net.droidjack.server") and
		androguard.service(/net\.droidjack\.server\./)
		
		
}
