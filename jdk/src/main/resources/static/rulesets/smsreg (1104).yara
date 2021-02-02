/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSReg
    Rule id: 1104
    Created at: 2016-01-06 12:55:21
    Updated at: 2016-01-06 15:44:18
    
    Rating: #0
    Total detections: 164
*/

rule smsreg
{
	meta:
		description = "SMSReg"
		sample = "f861d78cc7a0bb10f4a35268003f8e0af810a888c31483d8896dfd324e7adc39"

	strings:
		$a = {F0 62 98 9E C7 52 A6 26 92 AB C1 31 63}

	condition:
		all of them
}
