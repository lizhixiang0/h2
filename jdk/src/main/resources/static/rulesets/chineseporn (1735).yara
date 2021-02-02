/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: ChinesePorn
    Rule id: 1735
    Created at: 2016-07-27 08:36:50
    Updated at: 2016-10-04 14:17:20
    
    Rating: #3
    Total detections: 740768
*/

import "androguard"
import "cuckoo"

rule ChinesePorn
{
	condition:
		androguard.url(/apk.iuiss.com/i) or
		androguard.url(/a0.n3117.com/i) or
		androguard.url(/http:\/\/www.sky.tv/) or
		cuckoo.network.dns_lookup(/apk.iuiss.com/i) or
		cuckoo.network.dns_lookup(/a0.n3117.com/i)
}

rule Shedun
{

	strings:
		$a = "hehe you never know what happened!!!!"
		$b = "madana!!!!!!!!!"

	condition:
 		all of them
		
}
