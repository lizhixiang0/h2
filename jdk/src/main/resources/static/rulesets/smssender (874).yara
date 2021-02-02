/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: SmsSender
    Rule id: 874
    Created at: 2015-09-29 21:34:36
    Updated at: 2015-10-08 10:18:12
    
    Rating: #1
    Total detections: 12822
*/

import "androguard"


rule smsSender
{
	meta:
		description = "Sends SMS. Final number is obfuscated, but easy to read. Code below."
		// Number10 is the final number.
	strings:
		$mfprice = "236"
		$price2 = "94.70"

	condition:
		androguard.package_name("com.software.application") and ($mfprice or $price2)
		
}
