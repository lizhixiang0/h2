/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: locker_ccm
    Rule id: 1942
    Created at: 2016-11-01 18:54:41
    Updated at: 2016-11-01 18:56:15
    
    Rating: #0
    Total detections: 2759
*/

rule locker : ccm
{
	meta:
		description = "This rule detects pornlocker for ccm"
		sample = "e09849761ab3e41e9b88fe6820c0b536af4dbbb016a75248b083c25ce3736592"
	strings:
		$S_16_7160 = { 71 10 ?? ?? 04 00 0a 00 39 00 0b 00 60 00 02 00 13 01 13 00 34 10 06 00 71 30 ?? ?? 42 03 0e 00 60 00 02 00 13 01 0e 00 34 10 06 00 71 30 ?? ?? 42 03 28 f6 71 20 ?? ?? 42 00 28 f2 }
		$S_128_2820 = { 28 06 22 00 ?? 00 70 10 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? 0e 00 }
		$S_16_6230 = { 62 00 ?? 00 71 20 ?? ?? 01 00 0c 00 71 10 ?? ?? 00 00 71 20 ?? ?? 02 00 0e 00 0d 00 28 fe }
		$S_714_2822 = { 28 06 22 01 ?? 00 70 10 ?? ?? 01 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 }
		$S_32_1298 = { 12 04 71 20 ?? ?? 65 00 0c 00 71 20 ?? ?? 50 00 0c 00 1f 00 ?? ?? 1f 00 ?? ?? 71 10 ?? ?? 00 00 0c 01 71 10 ?? ?? 01 00 0c 01 21 02 21 73 b0 32 71 20 ?? ?? 21 00 0c 01 1f 01 ?? ?? 1f 01 ?? ?? 21 02 21 73 71 53 ?? ?? 47 21 21 02 71 52 ?? ?? 40 41 71 20 ?? ?? 65 00 0c 00 71 30 ?? ?? 50 01 0e 00 }

	

	condition:
		all of them
		
}
