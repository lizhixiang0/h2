/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: GAGA01 SMSSender
    Rule id: 614
    Created at: 2015-06-19 22:03:58
    Updated at: 2015-08-06 15:20:21
    
    Rating: #1
    Total detections: 64960
*/

import "cuckoo"

rule gaga01:SMSSender
{
	condition:
		cuckoo.network.dns_lookup(/gaga01\.net/)
}
