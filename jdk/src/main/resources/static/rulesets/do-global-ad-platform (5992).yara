/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: deletescape
    Rule name: DO Global Ad Platform
    Rule id: 5992
    Created at: 2019-10-24 12:44:11
    Updated at: 2019-10-24 12:54:32
    
    Rating: #0
    Total detections: 0
*/

import "cuckoo"


rule DOGlobal
{
	meta:
		description = "Evidences of DO global advertisement library / Adware "

	condition:
		cuckoo.network.dns_lookup(/do.global/) or cuckoo.network.dns_lookup(/do-global.com/) or cuckoo.network.dns_lookup(/ad.duapps.com/)
		
}
