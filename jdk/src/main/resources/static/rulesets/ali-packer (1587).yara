/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Ali packer
    Rule id: 1587
    Created at: 2016-07-07 15:37:44
    Updated at: 2016-07-08 13:31:46
    
    Rating: #0
    Total detections: 2027
*/

rule packers : ali
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:

		$ali_1 = "libmobisecy.so"
		$ali_2 = "libmobisecy1.zip"

	condition:
		any of them
		
}
