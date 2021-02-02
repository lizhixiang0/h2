/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: PornoLocker
    Rule id: 5439
    Created at: 2019-04-10 08:06:17
    Updated at: 2019-04-10 09:51:08
    
    Rating: #0
    Total detections: 56
*/

import "androguard"
import "file"
import "cuckoo"


rule PornoLocker
{
	condition:
		cuckoo.network.dns_lookup(/soso4ki.ru/) or
		cuckoo.network.dns_lookup(/zapisulka.ru/)
		
}
