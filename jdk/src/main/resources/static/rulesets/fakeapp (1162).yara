/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: FakeApp
    Rule id: 1162
    Created at: 2016-01-27 02:30:19
    Updated at: 2016-02-21 14:43:53
    
    Rating: #0
    Total detections: 59273
*/

//rule updated with new fraudulent domains. 20160221

import "androguard"
import "cuckoo"

rule FakeApp
{
	meta:
		description = "FakeApp installer from fake developers"
		sample = "047b5ae5d7dddc035076b146e8d4548c877c78ab10686e795a354d497f72c321"
  condition:
    androguard.certificate.sha1("70A979A8E7C51EF068B7C41C2ECD2FDDB333C35C") or
	androguard.certificate.sha1("762E0CF7220044FC3374E05C395DF2C4FA4CBD9B") or
	androguard.certificate.sha1("ABB4A1C5B5E1F8E7208E20C32DA3F92D20CC5F4F") or
	androguard.certificate.sha1("F0A46A31E0446DC68CF270249E2111C6FA5A29BF") or
	androguard.certificate.sha1("CA6AAAD3963325E26734455482780ED2599B71AD") or
	androguard.certificate.sha1("595E399D88FD8C526748C39369CB546C3D2C8871") or
	androguard.certificate.subject(/Attacker Inc\./) or
	androguard.certificate.subject(/Attacker corp\./)
}

rule AddsDomains
{
	meta:
		description = "Fraudulent domains used in Ads Campaigns"
		sample = "3516eb210aad7f05c8c2d5485905308714d9fe6c898cfd8e35cb247475846261"
	strings:
		$1 = "zzwx.ru/" wide ascii
		$2 = "zwx.ru/" wide ascii	
		$3 = "sppromo.ru/" wide ascii
		$4 = "tdslsd.ru/" wide ascii
		$5 = "cldrm.com/" wide ascii
		$6 = "clmbtrk.com/" wide ascii
		$7 = "cldlr.com/" wide ascii
		$8 = "wezzx.ru/" wide ascii
		$9 = "leno.ml/" wide ascii		
		$10 = "winbv.nl/" wide ascii
		
	condition:
		1 of them or
		cuckoo.network.dns_lookup(/zzwx.ru/) or
		cuckoo.network.dns_lookup(/zwx.ru/) or
		cuckoo.network.dns_lookup(/sppromo.ru/) or
		cuckoo.network.dns_lookup(/tdslsd.ru/) or
		cuckoo.network.dns_lookup(/cldrm.com/) or
		cuckoo.network.dns_lookup(/clmbtrk.com/) or
		cuckoo.network.dns_lookup(/cldlr.com/) or
		cuckoo.network.dns_lookup(/wezzx.ru/) or
		cuckoo.network.dns_lookup(/leno.ml/) or
		cuckoo.network.dns_lookup(/winbv.nl/)		
}
