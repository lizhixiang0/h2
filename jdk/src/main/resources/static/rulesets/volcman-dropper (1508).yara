/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Volcman Dropper
    Rule id: 1508
    Created at: 2016-06-14 15:33:33
    Updated at: 2016-09-16 13:35:28
    
    Rating: #0
    Total detections: 534
*/

import "androguard"
import "file"
import "cuckoo"


rule volcman_dropper
{
	meta:
		description = "Dropper"
		sample = "322dfa1768aac534989acba5834fae4133177fec2f1f789d9a369ebbf1f00219"
		certificate = "8AA6F363736B79F51FB7CF3ACFC75D80F051325F"

	condition:
		cuckoo.network.dns_lookup(/advolcman\.com/)
		or cuckoo.network.dns_lookup(/woltrezmhapplemouse\.com/)
		or cuckoo.network.dns_lookup(/aerovolcman\.com/)
}
