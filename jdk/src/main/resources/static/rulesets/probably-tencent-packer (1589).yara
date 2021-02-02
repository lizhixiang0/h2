/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: probably tencent packer
    Rule id: 1589
    Created at: 2016-07-07 15:38:39
    Updated at: 2016-07-08 13:30:30
    
    Rating: #0
    Total detections: 25432
*/

rule packers : tencent
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$tencent_1 = "libmain.so"
		$tencent_2 = "libshell.so"

	condition:
		2 of them
		
}
