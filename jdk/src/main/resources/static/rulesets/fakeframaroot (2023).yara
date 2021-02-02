/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Fake.Framaroot
    Rule id: 2023
    Created at: 2016-12-07 09:03:51
    Updated at: 2016-12-07 09:05:12
    
    Rating: #0
    Total detections: 1271
*/

import "androguard"

rule fake_framaroot
{
	meta:
		description = "This rule detects fake framaroot apks"
		sample = "41764d15479fc502be6f8b40fec15f743aeaa5b4b63790405c26fcfe732749ba"

	condition:
		androguard.app_name(/framaroot/i) and
		not androguard.certificate.sha1("3EEE4E45B174405D64F877EFC7E5905DCCD73816")
		
}
