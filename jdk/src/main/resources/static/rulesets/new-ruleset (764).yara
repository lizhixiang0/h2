/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: feng01
    Rule name: New Ruleset
    Rule id: 764
    Created at: 2015-08-10 04:57:07
    Updated at: 2015-08-10 04:57:30
    
    Rating: #1
    Total detections: 843
*/

rule ransomware : svpeng
{
	meta:
		description = "Ransomware"
		in_the_wild = true

	strings:
		$a =  {6e 64 20 79 6f 75 72 27 73 20 64 65 76 69 63 65 20 77 69 6c 6c 20 72 65 62 6f 6f 74 20 61 6e 64}
		$b = "ADD_DEVICE_ADMI"

	condition:
		$a and $b
}
