/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: fakeInstallers
    Rule id: 1023
    Created at: 2015-11-18 09:16:09
    Updated at: 2015-11-18 09:17:33
    
    Rating: #1
    Total detections: 86556
*/

import "androguard"

rule Ransom {
	meta: 
		description = "ransomwares"	
	strings:
		$a = "!2,.B99^GGD&R-"
		$b = "22922222222222222222Q^SAAWA"

	condition:
		$a or $b
}

rule fakeInstalls {
	meta:
	 description = "creates fake apps (usually low sized) for malicious purposes."
	
	condition:
		androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
}
