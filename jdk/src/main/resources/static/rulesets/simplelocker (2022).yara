/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SimpleLocker
    Rule id: 2022
    Created at: 2016-12-07 08:54:49
    Updated at: 2016-12-07 08:57:40
    
    Rating: #0
    Total detections: 202
*/

import "androguard"



rule locker : ransomware
{
	meta:
		description = "This rule detects ransomware apps"
		sample = "41764d15479fc502be6f8b40fec15f743aeaa5b4b63790405c26fcfe732749ba"

	condition:
		androguard.package_name("com.simplelocker")
}
