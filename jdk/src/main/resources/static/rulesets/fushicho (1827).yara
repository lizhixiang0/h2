/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: Fushicho
    Rule id: 1827
    Created at: 2016-09-20 02:51:36
    Updated at: 2016-10-25 07:56:04
    
    Rating: #0
    Total detections: 156
*/

import "androguard"
import "file"
import "cuckoo"


rule Fushicho : official
{
	meta:
		description = "http://blog.avlsec.com/2016/09/3788/fushicho/"


	condition:
		androguard.url(/mmchongg\.com/) or
		androguard.url(/yggysa\.com/) or
		cuckoo.network.dns_lookup(/mmchongg/) or
		cuckoo.network.dns_lookup(/yggysa/) or
		cuckoo.network.http_request(/abcll0/) or
		cuckoo.network.http_request(/us:9009\/gamesdk\/doroot\.jsp\?/)
		
}
