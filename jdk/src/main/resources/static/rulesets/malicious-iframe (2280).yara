/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Malicious iFrame
    Rule id: 2280
    Created at: 2017-03-02 23:29:29
    Updated at: 2017-03-14 21:40:58
    
    Rating: #0
    Total detections: 94
*/

import "androguard"
import "file"
import "cuckoo"


rule Malicious_iFrame

{
	meta:
		description = "This rule detectes apps with hidden malicious iframe"
		sample = "d6289fa1384fab121e730b1dce671f404950e4f930d636ae66ded0d8eb751678"

	strings:
	
		$e = "Brenz.pl"
		$a = "iframe style=\"height:1px"
		$b = "frameborder=0 width=1></iframe"

	condition:
		($e and androguard.certificate.sha1("69CE857378306A329D1DCC83A118BC1711ABA352")) or
		($a and $b and $e)
		
}
