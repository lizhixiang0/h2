/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: NetTraffic_Root_zk
    Rule id: 3357
    Created at: 2017-08-10 03:03:29
    Updated at: 2017-08-10 12:25:16
    
    Rating: #0
    Total detections: 114
*/

import "androguard"
import "file"
import "cuckoo"

rule Root_zk : NetTraffic
{
	meta:
		description = "This rule detects root related about zookxxxxxx "
		sample = "fa48660370dc236ad80b5192fb1992d53f8d6e2cd8b2aa04ba9e9b3856aa9d96"
		detail = ""

	strings:
		$str_Matrix_0 = "/MatrixClient;"
		$str_Matrix_1 = "getLogTag"
		
		$str_Config_0 = "META-INF/SCONFIG"
		//$str_Config_1 = "dexURL"


	condition:
		all of ($str_Matrix_*) or
		
		any of ($str_Config_*) or
		
		cuckoo.network.dns_lookup(/m\.fruitnotlike\.com/) or
		cuckoo.network.dns_lookup(/n\.dingda585\.com/) or
		cuckoo.network.dns_lookup(/p\.bringbiggame\.com/) or
		cuckoo.network.dns_lookup(/p\.zccfo\.com/) or
		cuckoo.network.dns_lookup(/n\.52bangke\.com/) or
		cuckoo.network.dns_lookup(/m\.hothomemonkey\.com/) or
		cuckoo.network.dns_lookup(/p\.bpai360\.com/) or
		cuckoo.network.dns_lookup(/p\.sportnotlike\.com/) or
		cuckoo.network.dns_lookup(/p\.aoziclub\.com/) or
		cuckoo.network.dns_lookup(/p\.kakaoya\.com/) or
		cuckoo.network.dns_lookup(/n\.migodycb\.com/) or
		cuckoo.network.dns_lookup(/m\.justforsomefun\.com/) or
		cuckoo.network.dns_lookup(/p\.shuyuan168\.com/)
}
