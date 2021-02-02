/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Bangcle packer
    Rule id: 1585
    Created at: 2016-07-07 15:36:45
    Updated at: 2016-07-08 13:31:57
    
    Rating: #0
    Total detections: 11263
*/

rule packers : bangcle
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$bangcle_1 = "libsecmain.so"
		$bangcle_2 = "libsecexe.so"
		$bangcle_3 = "bangcleplugin"
		

	condition:
		all of them
		
}
