/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Developers_with_known_malicious_apps
    Rule id: 2125
    Created at: 2017-01-11 23:32:20
    Updated at: 2017-03-03 20:04:17
    
    Rating: #0
    Total detections: 15717
*/

import "androguard"
import "file"
import "cuckoo"


rule Developers_with_known_malicious_apps
{
	meta:
		description = "This rule lists app from developers with a history of malicious apps"
		sample = "69b4b32e4636f1981841cbbe3b927560"

	strings:
	
		$a = "Londatiga"
		$b = "evaaee3ge3aqg"
		$c = "gc game"
		$d = "jagcomputersecuitity"
		$e = "aaron balder"
	condition:
		($a and androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")) or
		(androguard.certificate.sha1("1CA6B5C6D289C3CCA9F9CC0E0F616FBBE4E0573B")) or
		($b and androguard.certificate.sha1("79981C39859BFAC4CDF3998E7BE26148B8D94197")) or
		($c and androguard.certificate.sha1("CA763A4F5650A5B685EF07FF31587FA090F005DD")) or
		($d and androguard.certificate.sha1("4CC79D06E0FE6B0E35E5B4C0CB4F5A61EEE4E2B8")) or
		($e and androguard.certificate.sha1("69CE857378306A329D1DCC83A118BC1711ABA352")) 
		
}
