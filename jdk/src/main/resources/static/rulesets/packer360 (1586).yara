/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: packer360
    Rule id: 1586
    Created at: 2016-07-07 15:37:15
    Updated at: 2016-07-08 13:30:10
    
    Rating: #0
    Total detections: 28112
*/

rule packers : i360
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"
		
	condition:
		2 of them
		
}
