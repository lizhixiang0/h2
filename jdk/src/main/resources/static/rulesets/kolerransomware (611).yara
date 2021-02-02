/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: Koler.Ransomware
    Rule id: 611
    Created at: 2015-06-18 12:23:14
    Updated at: 2016-02-18 16:20:31
    
    Rating: #0
    Total detections: 607
*/

import "cuckoo"

rule koler_domains
{
	meta:
		description = "Old Koler.A domains examples"
		sample = "2e1ca3a9f46748e0e4aebdea1afe84f1015e3e7ce667a91e4cfabd0db8557cbf"

	condition:
		cuckoo.network.dns_lookup(/police-scan-mobile.com/) or
		cuckoo.network.dns_lookup(/police-secure-mobile.com/) or
		cuckoo.network.dns_lookup(/mobile-policeblock.com/) or
		cuckoo.network.dns_lookup(/police-strong-mobile.com/) or
		cuckoo.network.dns_lookup(/video-porno-gratuit.eu/) or
		cuckoo.network.dns_lookup(/video-sartex.us/) or 
		cuckoo.network.dns_lookup(/policemobile.biz/)
}

rule koler_builds
{
	meta:
		description = "Koler.A builds"

	strings:
		$0 = "buildid" wide ascii
		$a = "DCEF055EEE3F76CABB27B3BD7233F6E3" wide ascii
		$b = "C143D55D996634D1B761709372042474" wide ascii
		
	condition:
		$0 and ($a or $b)
		
}

rule koler_strings
{
	meta:
		description = "Koler strings"

	strings:
		$0 = "You device will be unprotectable. Are you sure?" wide ascii
		
	condition:
		1 of them
		
}

rule koler_class
{
	meta:
		description = "Koler.A class"

	strings:
		$0 = "FIND_VALID_DOMAIN" wide ascii
		$a = "6589y459" wide ascii
		
	condition:
		all of them
		
}

rule koler_D
{
	meta:
		description = "Koler.D class"

	strings:
		$0 = "ZActivity" wide ascii
		$a = "Lcom/android/zics/ZRuntimeInterface" wide ascii
		
	condition:
		all of them
		
}
